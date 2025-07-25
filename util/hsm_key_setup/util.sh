softhsm2-util --init-token --slot 0 --label car-token --so-pin 12345 --pin 12345

pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so \
	--login \
	--pin "12345" \
	--write-object hsm_private.pem \
	--type privkey \
	--id 00 \
	--label "HSM-PRIV"
pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so \
	--login \
	--pin "12345" \
	--write-object ecu1_public.pem \
	--type pubkey \
	--id 01 \
	--label "ECU1PUBL"
pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so \
	--login \
	--pin "12345" \
	--write-object ecu2_public.pem \
	--type pubkey \
	--id 02 \
	--label "ECU2PUBL"
pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so \
	--login \
	--pin "12345" \
	--write-object ecu3_public.pem \
	--type pubkey \
	--id 03 \
	--label "ECU3PUBL"
pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so \
	--login \
	--pin "12345" \
	--write-object ecu4_public.pem \
	--type pubkey \
	--id 04 \
	--label "ECU4PUBL"
pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so \
	--login \
	--pin "12345" \
	--write-object ecu5_public.pem \
	--type pubkey \
	--id 05 \
	--label "ECU5PUBL"
pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so \
	--login \
	--pin "12345" \
	--write-object ecu6_public.pem \
	--type pubkey \
	--id 06 \
	--label "ECU6PUBL"
pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so \
	--login \
	--pin "12345" \
	--write-object ecu7_public.pem \
	--type pubkey \
	--id 07 \
	--label "ECU7PUBL"
pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so \
	--login \
	--pin "12345" \
	--write-object ecu8_public.pem \
	--type pubkey \
	--id 08 \
	--label "ECU8PUBL"
