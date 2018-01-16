# OpenVPN Access Server MAC address checking post_auth script.
# This script can be used with LOCAL, PAM, LDAP, and RADIUS authentication.
#
# Please note: RADIUS case insensitivity may lead to the system recognizing
# Billy.Bob and billy.bob as 2 separate accounts, when using RADIUS.
#
#
#
# - How it works:
# Whenever a user logs on and has no MAC address registered yet in the user
# properties database of the Access Server, then the MAC address will be
# stored in that database. Any following attempt to log in under that user
# account will require that the connection is made from the same MAC address.
# The MAC address is taken from the first ethernet network connection the VPN
# client finds. Only the OpenVPN Connect Client latest version is supported,
# but open source clients may also work (some have been tested to work).
#
# If the first_login_ip_addr variable is set to a specific IP address, then
# only first time login attempts will be accepted from that address. For
# example if you only want to allow MAC address registrations from one
# computer or network, enter that network's public IP address in this
# script. You can find this parameter further on in the script. For example:
#
# first_login_ip_addr="123.45.67.89"
#
# If it is left empty, then first time logins will be accepted from any IP
# address. The choice of adding this extra safety requirement is up to you.
# It is also a way of denying users to register themselves, forcing you as
# an administrator to register all accounts yourself. If you set it to an
# impossible value like "NONE" then all MAC address registrations must be
# done through the command line of the Access Server by an administrator.
#
#
#
# - Notes regarding connection profile types
# This script works with all 3 types of connection profiles. That is,
# user-locked, server-locked, and autologin. All will adhere to the
# restrictions in this post_auth script. The Connect Client may end up
# looping endlessly when it is being denied access, in which case you need
# to stop the connection by opening the menu and clicking 'disconnect',
# after which the solution to this problem is to correct the MAC address
# registration.
#
#
#
# - Notes regarding client software
# OpenVPN Connect Client for Windows and Macintosh is supported.
#
# The following clients have also been tested to work but are not under
# any guarantee of support by OpenVPN Technologies Inc.:
#
# The open source client called 'openvpn' on Linux.
# The open source client called 'OpenVPN GUI' on Windows.
# The open source client called 'Tunnelblick' on Macintosh.
# Most open source clients based on 'openvpn' binary should work.
#
# Please note that for all clients it is assumed that you are using a
# recent version. If you make a connection with your client software of
# choice and it turns out that it is not reporting a MAC address to the
# Access Server then the first thing to check is that you have the latest
# version of that software with the most recent version of the OpenVPN
# binary core that you can get.
#
#
#
# - How to install/update the script
# This file has to be saved somewhere on the Access Server. The filename is
# not important, but let's say it is mac.py and that it is stored in the
# following folder: /root/mac.py
# In that case use the following command lines as a guide to load this
# script into the Access Server, and reload with the new settings:
#
# sudo su
# cd /usr/local/openvpn_as/scripts
# ./sacli -k auth.module.post_auth_script --value_file=/root/mac.py ConfigPut
# ./sacli start
#
#
#
# - How to uninstall the script
# The script is loaded into the configuration database, and can be removed
# from there with the following commands. Note that this action does not
# remove the MAC addresses already saved in the database, but these will
# simply be ignored and not cause further issues.
#
# sudo su
# cd /usr/local/openvpn_as/scripts
# ./sacli -k auth.module.post_auth_script ConfigDel
# ./sacli start
#
#
#
# - How to unregister/reset a MAC address
# If for some reason the user account is being used on another system or
# for some reason the MAC address has changed, you will need to remove the
# MAC address that is currently stored and locked for that particular user.
# To do this you can use the following commands to remove the saved MAC
# address for the user "exampleuser" and reload the server:
#
# sudo su
# cd /usr/local/openvpn_as/scripts
# ./sacli -u "exampleuser" -k "pvt_hw_addr" UserPropDel
# ./sacli start
#
#
#
# - How to manually register/update a MAC address
# If you want to manually specify the address for an account, you can do
# so with the following commands, where "exampleuser" is the user account
# name and where "00:01:02:ab:cd:ef" is the MAC address. Please stick to
# lower case as upper case is not what is used for the MAC address check.
# Please keep in mind that this lower/upper case sensitivity is a factor
# especially when using LDAP, in which the LDAP server reports the name
# back during the login phase. In other words, LDAP case is leading.
#
# sudo su
# cd /usr/local/openvpn_as/scripts
# ./sacli -u "exampleuser" -k "pvt_hw_addr" -v "00:01:02:ab:cd:ef" UserPropPut
# ./sacli start
#
#
#
# - How to debug any problems
# If you use the restriction to allow only MAC address regisrations from a
# specific IP address as explained in this file, then please undo that
# particular restriction and install/update the post_auth script again,
# and reload the settings again, as explained earlier in this file.
#
# Any information that the post_auth script outputs to the log file can
# be found in the /var/log/openvpnas.log (by default) on most Access Server
# setups. You can easily filter for specific messages from post_auth
# with these commands:
#
# sudo su
# cat /var/log/openvpnas.log | grep "POST_AUTH"
#
# If there are further problems or questions you can contact the support
# ticket system at www.openvpn.net by signing in and clicking 'support'.
# Please note that customized python post_auth scripts are not under
# support by OpenVPN Technologies Inc.
#
#
#
# Script last updated in September 2016


import re
# not necessary for openvpnas

#from pyovpn.plugin import *

# Optionally set this string to a known public IP address (such as the
# public IP address of machines connecting from a trusted location, such
# as the corporate LAN).  If set, all users must first login from this
# IP address, where the machine's hardware (MAC) address will be recorded.
first_login_ip_addr=""

# If False or undefined, AS will call us asynchronously in a worker thread.
# If True, AS will call us synchronously (server will block during call),
# however we can assume asynchronous behavior by returning a Twisted
# Deferred object.
SYNCHRONOUS=False

# this function is called by the Access Server after normal authentication
def post_auth(authcred, attributes, authret, info):
    print "********** POST_AUTH", authcred, attributes, authret, info

    # get user's property list, or create it if absent
    proplist = authret.setdefault('proplist', {})

    # user properties to save - we will use this to pass the hw_addr_save property to be
    # saved in the user property database.
    proplist_save = {}

    error = ""

    # If a VPN client authentication attempt is made, do these steps:
    # Check if there is a known MAC address for this client
    # If not, register it
    # If yes, check it
    #
    # An additional optional requirement is that first time registration must occur
    # from a specific IP address, as specified in the first_login_ip_addr set above
    #
    # The 'error' text goes to the VPN client and is shown to the user.
    # The 'print' lines go to the log file at /var/log/openvpnas.log (by default).

    if attributes.get('vpn_auth'):                  # only do this for VPN authentication
        hw_addr = authcred.get('client_hw_addr')    # MAC address reported by the VPN client
        username = authcred.get('username')         # User name of the VPN client login attempt
        clientip = authcred.get('client_ip_addr')   # IP address of VPN client login attempt
        if hw_addr:
            hw_addr_save = proplist.get('pvt_hw_addr') # saved MAC addr property
            if hw_addr_save:
                if hw_addr_save != hw_addr:
                    error = "The hardware MAC address reported by this VPN client does not match the registered MAC address."
                    print "***** POST_AUTH MAC CHECK: account user name    : %s" % username
                    print "***** POST_AUTH MAC CHECK: client IP address    : %s" % clientip
                    print "***** POST_AUTH MAC CHECK: locked MAC address   : %s" % hw_addr
                    print "***** POST_AUTH MAC CHECK: expected MAC address : %s" % hw_addr_save
                    print "***** POST_AUTH MAC CHECK: connection attempt   : FAILED"
                else:
                    print "***** POST_AUTH MAC CHECK: account user name    : %s" % username
                    print "***** POST_AUTH MAC CHECK: client IP address    : %s" % clientip
                    print "***** POST_AUTH MAC CHECK: locked MAC address   : %s" % hw_addr
                    print "***** POST_AUTH MAC CHECK: expected MAC address : %s" % hw_addr_save
                    print "***** POST_AUTH MAC CHECK: connection attempt   : SUCCESS"

            else:
                # First login by this user, save MAC addr.
                if not first_login_ip_addr or first_login_ip_addr == clientip:
                    proplist_save['pvt_hw_addr'] = hw_addr
                    print "***** POST_AUTH MAC CHECK: account user name    : %s" % username
                    print "***** POST_AUTH MAC CHECK: client IP address    : %s" % clientip
                    print "***** POST_AUTH MAC CHECK: locked MAC address   : %s" % hw_addr
                    print "***** POST_AUTH MAC CHECK: action taken         : MAC address learned and locked."
                    print "***** POST_AUTH MAC CHECK: connection attempt   : SUCCESS"
                else:
                    error = "Your attempt to login from a system not approved for MAC address registration has been denied."
                    print "***** POST_AUTH MAC CHECK: account user name    : %s" % username
                    print "***** POST_AUTH MAC CHECK: client IP address    : %s" % clientip
                    print "***** POST_AUTH MAC CHECK: action taken         : attempt to register client MAC address from unknown system denied."
                    print "***** POST_AUTH MAC CHECK: connection attempt   : FAILED"

        else:
            error = "VPN client is not reporting a MAC address. Please verify that Connect Client latest version is being used."
            print "***** POST_AUTH MAC CHECK: account user name    : %s" % username
            print "***** POST_AUTH MAC CHECK: client IP address    : %s" % clientip
            print "***** POST_AUTH MAC CHECK: MAC address reported : NONE"
            print "***** POST_AUTH MAC CHECK: connection attempt   : FAILED"

    # process error, if one occurred
    if error:
        authret['status'] = FAIL
        authret['reason'] = error          # this error string is written to the server log file
        authret['client_reason'] = error   # this error string is reported to the client user

    return authret, proplist_save
