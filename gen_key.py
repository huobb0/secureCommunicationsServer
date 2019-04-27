#!/usr/bin/env python3
import sys

from rsa import key, common
(pub_key, priv_key) = key.newkeys(2048)

fd = open(sys.argv[1],'wb')
fd.write(pub_key.save_pkcs1(format='PEM'))
fd.close()

fd = open(sys.argv[2],'wb')
fd.write(priv_key.save_pkcs1(format='PEM'))
fd.close()
