<!---
	rsa.cfc (https://github.com/ggfx/coldfusion-rsa)
	Component for asymmetric key cryptograph using java security, it has these methods:
	-	 create_key_pair: creates a RSA key-pair, returns a struct with public and private key
	-	 encrypt_string:  encrypts a text-string with public or private key (for private key provide parameter key_type='private') returns base64 encoded string
	-	 decrypt_string:  decrypts a base64 string with public or private key (for public key provide parameter key_type='public') returns plain text-string

	Can be used with BouncyCastleProvider e.g. http://www.bouncycastle.org/download/bcprov-jdk15on-149.jar
	For BouncyCastle jar you have to use JavaLoader (https://github.com/markmandel/JavaLoader) as well

	@Author	Cornelius Rittner
	@Website http://ggfx.org
	@Date	25.07.2013
--->
<cfcomponent name="rsa" hint="Creates KeyPairs, encrypts and decrypts strings">

	<cffunction name="init" hint="Constructor" access="public" returntype="rsa" output="false">
		<cfargument name="JavaLoader" type="string" required="false" default="" hint="path to component with dot-notation e.g. javaloader.javaloader">
		<cfargument name="bouncycastle_path" type="string" required="false" default="" hint="full directory path and filename to jar">
		<cfset var ary_paths = ArrayNew(1)>

		<!--- try to load JavaLoader and BouncyCastle --->
		<cfif arguments.JavaLoader NEQ "" AND arguments.bouncycastle_path NEQ "">
			<cftry>
				<cfset ary_paths[1] = arguments.bouncycastle_path>
				<cfif ListLast(arguments.JavaLoader,".") EQ "cfc" AND ListLen(arguments.JavaLoader,".") GT 1>
					<cfset arguments.JavaLoader = ListDeleteAt(arguments.JavaLoader,ListLen(arguments.JavaLoader,"."),".")>
				</cfif>
				<cfset variables.JavaLoader = createObject("component",arguments.JavaLoader).init(ary_paths) />
				<cfset this.bc = variables.JavaLoader.create("org.bouncycastle.jce.provider.BouncyCastleProvider").init()>
				<cfcatch>
					<cfthrow message="JavaLoader or BouncyCastle failed to load" detail="#cfcatch.Detail#">
				</cfcatch>
			</cftry>
		</cfif>
		<cfreturn this />
	</cffunction>

	<cffunction name="create_key_pair" hint="uses KeyPairGenerator to create object" access="public" returntype="struct" output="false">
		<cfargument name="key_size" type="numeric" default="512" hint="1024, 2048, 4096.. the larger the longer the request takes">
		<cfargument name="output_type" type="string" default="string" hint="object, binary or string">

		<cfset var local = structNew()>

		<cfset var obj_kpg = createObject("java","java.security.KeyPairGenerator")>

		<cfset local.out = structNew()>

			<!--- Get an instance of the provider for the RSA algorithm. --->
			<cfif structKeyExists(this,"bc") AND isObject(this.bc)>
				<cfset local.rsa = obj_kpg.getInstance("RSA",this.bc)>
			<cfelse>
				<cfset local.rsa = obj_kpg.getInstance("RSA")>
			</cfif>

			<!--- Get an instance of secureRandom, we'll need this to initialize the key generator --->
			<cfset local.sr = createObject('java', 'java.security.SecureRandom').init()>

			<!--- Initialize the generator by passing in the size of key we want, and a strong pseudo-random number generator (PRNG) --->
			<cfset local.rsa.initialize(arguments.key_size, local.sr)>

			<!--- This will create two keys, one public, and one private --->
			<cfset local.kp = local.rsa.generateKeyPair()>

			<!--- Get the two keys. --->
			<cfset local.out.private_key = local.kp.getPrivate()>
			<cfset local.out.public_key = local.kp.getPublic()>

			<cfif arguments.output_type NEQ "object">
				<cfset local.out.private_key = local.out.private_key.getEncoded()>
				<cfset local.out.public_key = local.out.public_key.getEncoded()>

				<!--- Retreive a Base64 Encoded version of the key. Can be stored in file or Database --->
				<cfif arguments.output_type EQ "string">
					<cfset local.out.private_key = toBase64(local.out.private_key)>
					<cfset local.out.public_key = toBase64(local.out.public_key)>
				</cfif>
			</cfif>

		<cfreturn local.out />

	</cffunction>

	<cffunction name="encrypt_string" hint="encrypts a text-string with RSA to a base64 encoded string" access="public" returntype="string" output="false">
	    <cfargument name="text" type="string" required="true" hint="plain input text-string" />
	    <cfargument name="key" type="any" required="true" />
		<cfargument name="key_type" type="string" default="public" hint="public or private">

		<cfset var local = structNew()>

	    <!--- Create a Java Cipher object and get a mode --->
	    <cfset var cipher = createObject('java', 'javax.crypto.Cipher').getInstance("RSA")>

			<cfif not isObject(arguments.key)>
				<cfset arguments.key = create_key_object_helper(arguments.key,arguments.key_type)>
			</cfif>

		    <!--- Initialize the Cipher with the mode and the key --->
		    <cfset cipher.init(cipher.ENCRYPT_MODE, arguments.key) />

		    <!--- Perform encryption of bytes, returns binary --->
		    <cfset local.encrypted = cipher.doFinal(arguments.text.getBytes("UTF-8")) />

		<!--- Convert binary to Base64 encoded string --->
	    <cfreturn toBase64(local.encrypted) />

	</cffunction>

	<cffunction name="decrypt_string" hint="decrypts a base64 encoded string with RSA to its value" access="public" returntype="string" output="false">
	    <cfargument name="text" type="string" required="true" hint="the encrypted value as Base64 encoded string" />
	    <cfargument name="key" type="any" required="true" />
		<cfargument name="key_type" type="string" default="private" hint="public or private">

		<cfset var local = structNew()>

	    <!--- Create a Java Cipher object and get a mode --->
	    <cfset var cipher = createObject('java', 'javax.crypto.Cipher').getInstance("RSA")>

			<cfif not isObject(arguments.key)>
				<cfset arguments.key = create_key_object_helper(arguments.key,arguments.key_type)>
			</cfif>

		    <!--- Initialize the cipher with the mode and the key --->
		    <cfset cipher.init(cipher.DECRYPT_MODE, arguments.key) />

		    <!--- Perofrm the decryption --->
		    <cfset local.decrypted = cipher.doFinal(toBinary(arguments.text)) />

	    <!--- Convert the bytes back to a string and return it --->
	    <cfreturn toString(local.decrypted,"UTF-8") />

	</cffunction>

	<cffunction name="create_key_object_helper" hint="creates an object out of a [base64 encoded] binary key" access="public" returntype="any" output="false">
		<cfargument name="key" type="any" required="yes" hint="key has to be binary or string">
		<cfargument name="type" type="string" required="yes" hint="public or private">

		<cfset var local = structNew()>

			<cfif not isBinary(arguments.key)>
				<cfset arguments.key = toBinary(arguments.key)>
			</cfif>

			<cfset local.key_factory = createObject("java", "java.security.KeyFactory").getInstance("RSA") />

			<cfif arguments.type EQ "public">
				<!--- create public key object --->
				<cfset local.spec	= createObject("java", "java.security.spec.X509EncodedKeySpec").init(arguments.key) />
				<cfset local.key	= local.key_factory.generatePublic(local.spec) />

			<cfelseif arguments.type EQ "private">
				<!--- create private key object --->
				<cfset local.spec	= createObject("java", "java.security.spec.PKCS8EncodedKeySpec").init(arguments.key) />
				<cfset local.key	= local.key_factory.generatePrivate(local.spec) />

			<cfelse>
				<cfset local.key = "">

			</cfif>

		<cfreturn local.key />

	</cffunction>

</cfcomponent>