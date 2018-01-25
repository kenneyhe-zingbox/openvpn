
Requirements:
  - Files expected to be in /home/openvpnas
  - docker-compose.py sets up the mysql services for MAC checking functionality
  - mac_wrapper.py needs to be run as plugin 
    (https://openvpn.net/index.php/access-server/docs/admin-guides/411-access-server-post-auth-script.html)
  - docker_mac.sh is bash script to connect to local or remote (in the future) mysql to retrieve MAC address list or MAC
  - selftest.py is functional testing for above
