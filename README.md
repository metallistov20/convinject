# SSH 'conversation' injections to automate CLI-based remote SMB adjustment

Idea behind the compilation environmant:

to deploy "libssh" we ought to compile (and install) "openssl". For this follow such step-by-step sequence:

STEP 1. 

https://www.openssl.org/source/old/1.0.0/, newer ones are unwished due the "ERROR:struct evp_cipher_ctx_st" issue

STEP 2.

replace docs.ORI with some newer docs; in case tyou face the problems related to old-Perl-syntax on "make install" stage

STEP 3.

compile and install "openssl":

   #./config
   #make
   #make install

And ensure that the stuff's been installed into  "/usr/local/ssl" )

STEP 4.

Download "libssh":

   #git clone git://git.libssh.org/projects/libssh.git libssh

And then, from neiboring folder, do the "cmake  -DCMAKE_INSTALL_PREFIX=/usr -DCMAKE_BUILD_TYPE=Debug ../libssh

Also useful: #cmake-gui & (configure & generate) 

Also useful: see "STEP 5" below

STEP 5. 

Edit the "CmakeCashe.TXT" to add the 

	//Path to a library.
	OPENSSL_CRYPTO_LIBRARY:FILEPATH=/usr/local/ssl/lib/libcrypto.a

	//Path to a file.
	OPENSSL_INCLUDE_DIR:PATH=/usr/local/ssl/include

	//Path to a library.
	OPENSSL_SSL_LIBRARY:FILEPATH=/usr/local/ssl/lib/libssl.a



STEP 6.

Once needed: change the line 189 [in FindOpenSSL.cmake] to

	REGEX "^.*define[\t ]+OPENSSL_VERSION_NUMBER[\t ]+0x[0-9][0-9][0-9][0-9][0-9][0-9].")

It fixes "old" REGEX syntax. More info at this URL: https://github.com/TrinityCore/TrinityCore/issues/9355
