BANNERS = {
    21: b"220 (vsFTPd 3.0.3)\r\n",
    22: b"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.11\r\n",
    23: b"Ubuntu 22.04.4 LTS\r\nlogin: ",
    25: b"220 mail.example.local ESMTP Postfix\r\n",
    80: b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.52 (Ubuntu)\r\n\r\n",
    443: b"HTTP/1.1 400 Bad Request\r\nServer: nginx/1.18.0\r\n\r\n",
    3306: b"\x0a8.0.35-0ubuntu0.22.04.1\x00",
    3389: b"\x03\x00\x00\x13\x0e\xd0\x00\x00\x12\x34\x00\x02\x00\x08\x00\x02\x00\x00\x00",
    5900: b"RFB 003.008\n",
    8080: b"HTTP/1.1 200 OK\r\nServer: Jetty(9.4.48.v20220622)\r\n\r\n",
}


def get_banner(port):
    # trap ports and banner ports can drift apart, so never blow up here.
    return BANNERS.get(port, b"220 fake service ready\r\n")
