<!---
	rsa.cfc (https://github.com/ggfx/coldfusion-rsa)
	Component for asymmetric key cryptograph using java security, it has these methods:
	-	 create_key_pair: creates a RSA key-pair, returns a struct with public and private key
	-	 encrypt_string:  encrypts a text-string with public or private key (for private key provide parameter key_type='private') returns base64 encoded string
	-	 decrypt_string:  decrypts a base64 string with public or private key (for public key provide parameter key_type='public') returns plain text-string

	Can be used with BouncyCastleProvider e.g. http://www.bouncycastle.org/download/bcprov-jdk15on-149.jar
	For BouncyCastle jar you have to use JavaLoader (https://github.com/markmandel/JavaLoader)

	@Author	Cornelius Rittner
	@Website http://ggfx.org
	@Date	25.07.2013
--->
<cfcomponent name="rsa" hint="Creates KeyPairs, encrypts and decrypts strings">

	<cffunction name="init" hint="Constructor" access="public" returntype="rsa" output="false">
		<cfargument name="JavaLoader" type="any" required="false" hint="JavaLoader object or path to component with dot-notation e.g. javaloader.javaloader">
		<cfargument name="bouncycastle_path" type="string" required="false" default="" hint="full directory path and filename to jar">
		<cfscript>
			var ary_paths = ArrayNew(1);

				/* Set path to BouncyCastle jar */
				if (arguments.bouncycastle_path NEQ "") {
					ary_paths[1] = arguments.bouncycastle_path;
				}

				/* Load BC with JavaLoader */
				if (structKeyExists(arguments,"JavaLoader") AND arrayLen(ary_paths) GT 0) {
					if (NOT isObject(arguments.JavaLoader) AND IsSimpleValue(arguments.JavaLoader)) {
						if (ListLast(arguments.JavaLoader,".") EQ "cfc" AND ListLen(arguments.JavaLoader,".") GT 1) {
							arguments.JavaLoader = ListDeleteAt(arguments.JavaLoader,ListLen(arguments.JavaLoader,"."),".");
						}
						this.JavaLoader = createObject("component",arguments.JavaLoader).init(ary_paths);
					} else {
						// Assume JavaLoader is already an object
						this.JavaLoader = arguments.JavaLoader.init(ary_paths);
					}
					this.bc = this.JavaLoader.create("org.bouncycastle.jce.provider.BouncyCastleProvider").init();
				}

			return this;
		</cfscript>
	</cffunction>

	<cffunction name="create_key_pair" hint="uses KeyPairGenerator to create object" access="public" returntype="struct" output="false">
		<cfargument name="key_size" type="numeric" default="512" hint="1024, 2048, 4096.. the larger the longer the request takes">
		<cfargument name="output_type" type="string" default="string" hint="object, binary or string">
		<cfscript>
			var local = structNew();
			var obj_kpg = createObject("java","java.security.KeyPairGenerator");

			local.out = structNew();

				/* Get an instance of the provider for the RSA algorithm. */
				if (structKeyExists(this,"bc") AND isObject(this.bc)) {
					local.rsa = obj_kpg.getInstance("RSA",this.bc);
				} else {
					local.rsa = obj_kpg.getInstance("RSA");
				}

				/* Get an instance of secureRandom, we'll need this to initialize the key generator */
				local.sr = createObject('java', 'java.security.SecureRandom').init();

				/* Initialize the generator by passing in the key size, and a strong pseudo-random number generator */
				local.rsa.initialize(arguments.key_size, local.sr);

				/* This will create both one public and one private key */
				local.kp = local.rsa.generateKeyPair();

				/* Get the two keys */
				local.out.private_key = local.kp.getPrivate();
				local.out.public_key = local.kp.getPublic();

				if (arguments.output_type NEQ "object") {
					local.out.private_key = local.out.private_key.getEncoded();
					local.out.public_key = local.out.public_key.getEncoded();

					/* Retreive a Base64 encoded version of the key. Can be stored in file or database */
					if (arguments.output_type EQ "string") {
						local.out.private_key = toBase64(local.out.private_key);
						local.out.public_key = toBase64(local.out.public_key);
					}
				}

			return local.out;
		</cfscript>
	</cffunction>

	<cffunction name="encrypt_string" hint="encrypts a text-string with RSA to a base64 encoded string" access="public" returntype="string" output="false">
		<cfargument name="text" type="string" required="true" hint="plain input text-string" />
		<cfargument name="key" type="any" required="true" />
		<cfargument name="key_type" type="string" default="public" hint="public or private">
		<cfscript>
			var local = structNew();
			/* Create a Java Cipher object and get a mode */
			var cipher = createObject('java', 'javax.crypto.Cipher').getInstance("RSA");

				if (NOT isObject(arguments.key)) {
					arguments.key = create_key_object_helper(arguments.key,arguments.key_type);
				}

				/* Initialize the Cipher with the mode and the key */
				cipher.init(cipher.ENCRYPT_MODE, arguments.key);

				/* Perform encryption of bytes, returns binary */
				local.encrypted = cipher.doFinal(arguments.text.getBytes("UTF-8"));

			/* Convert binary to Base64 encoded string */
	  		return toBase64(local.encrypted);
		</cfscript>
	</cffunction>

	<cffunction name="decrypt_string" hint="decrypts a base64 encoded string with RSA to its value" access="public" returntype="string" output="false">
		<cfargument name="text" type="string" required="true" hint="the encrypted value as Base64 encoded string" />
		<cfargument name="key" type="any" required="true" />
		<cfargument name="key_type" type="string" default="private" hint="public or private">
		<cfscript>
			var local = structNew();
			/* Create a Java Cipher object and get a mode */
			var cipher = createObject('java', 'javax.crypto.Cipher').getInstance("RSA");

				if (NOT isObject(arguments.key)) {
					arguments.key = create_key_object_helper(arguments.key,arguments.key_type);
				}

				/* Initialize the cipher with the mode and the key */
				cipher.init(cipher.DECRYPT_MODE, arguments.key);

				/* Perofrm the decryption */
				local.decrypted = cipher.doFinal(toBinary(arguments.text));

			/* Convert the bytes back to a string and return it */
			return toString(local.decrypted,"UTF-8");
		</cfscript>
	</cffunction>

	<cffunction name="create_key_object_helper" hint="creates an object out of a [base64 encoded] binary key" access="public" returntype="any" output="false">
		<cfargument name="key" type="any" required="yes" hint="key has to be binary or string">
		<cfargument name="type" type="string" required="yes" hint="public or private">
		<cfscript>
			var local = structNew();

				if (NOT isBinary(arguments.key)) {
					arguments.key = toBinary(arguments.key);
				}

				local.key_factory = createObject("java", "java.security.KeyFactory").getInstance("RSA");

				if (arguments.type EQ "public") {
					/* create public key object */
					local.spec	= createObject("java", "java.security.spec.X509EncodedKeySpec").init(arguments.key);
					local.key	= local.key_factory.generatePublic(local.spec);

				} else if (arguments.type EQ "private") {
					/* create private key object */
					local.spec	= createObject("java", "java.security.spec.PKCS8EncodedKeySpec").init(arguments.key);
					local.key	= local.key_factory.generatePrivate(local.spec);

				} else {
					local.key = "";
				}

			return local.key;
		</cfscript>
	</cffunction>

</cfcomponent>