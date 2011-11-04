// ---===[ AxMan (c) 2006 hdm[at]metasploit.com - All rights reserved.
	

//
// Modify the the blacklist in 'blacklist.js'
//

// Blacklisted Methods
var blmethods = new Array();
blmethods['ALL'] = new Array();

// Blacklisted Properties
var blproperties = new Array();
blproperties['ALL'] = new Array();

// Blacklisted Class IDs
var blclasses = new Array();


/*
 *
 * Evil values
 *
 */

// Embedded into strings to allow for regmon/filemon matches
var magic = "AXM4N";


// Evil property fuzzing values
var evilPropNum = new Array();
var evilPropStr = new Array();
var evilPropObj = new Array();

function createEvilPropArgs() {

	// Integers that often cause problems
	var evilPropNumBase = new Array(
		0x100000000,
		 0x80000000,
		 0x40000000,
		 0x20000000,
		 0x10000000,
		 0x01000000,
		 0x00100000,
		 0x00010000,
		 0x00001000,
		 0x00000100,
		 0x00000010,
		 0x00000001
	);

	evilPropNum = new Array();
	for (var i in evilPropNumBase) {
		var d = evilPropNumBase[i];

		evilPropNum.push(d);
		evilPropNum.push(d+1);
		evilPropNum.push(d+2);	
		evilPropNum.push(d-1);	
		evilPropNum.push(d-2);	
		evilPropNum.push(d * -1);
		evilPropNum.push(d * -2);
	}
	
	
	// Strings that often cause problems
	evilPropStr = new Array();
	
	var mib = "A";
	while (mib.length <= (1024*1024)) mib += mib;
	
	evilPropStr.push(mib.substring(0, 1));

	// Incrementing sizes around 64b breaks
	for (var i = 0; i < 8192; i++) {
		if ( (i % 64 == 0) || ((i-1) % 62 == 0) || ((i+1) % 62 == 0) )
			evilPropStr.push(mib.substring(0, i));
	}
	
	evilPropStr.push(mib.substring(0, 1024));
	evilPropStr.push(mib.substring(0, 16384));
	evilPropStr.push(mib.substring(0, 32768));
	evilPropStr.push(mib);

	
	// Format strings
	evilPropStr.push("%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n");
	evilPropStr.push("%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s");

	// Long file paths
	evilPropStr.push("C:\\"+mib.substring(0, 256));
	evilPropStr.push("C:\\"+mib.substring(0, 512));
	evilPropStr.push("C:\\"+mib.substring(0, 1024));
	evilPropStr.push("C:\\"+mib.substring(0, 8192));
	evilPropStr.push("C:\\"+magic);

	// Long HTTP
	evilPropStr.push("http://"+mib.substring(0, 256));
	evilPropStr.push("http://"+mib.substring(0, 512));
	evilPropStr.push("http://"+mib.substring(0, 1024));
	evilPropStr.push("http://"+mib.substring(0, 8192));
	evilPropStr.push("http://localhost/");
	evilPropStr.push("http://localhost/"+magic);

	// Long FTP	
	evilPropStr.push("ftp://"+mib.substring(0, 256));
	evilPropStr.push("ftp://"+mib.substring(0, 512));
	evilPropStr.push("ftp://"+mib.substring(0, 1024));
	evilPropStr.push("ftp://"+mib.substring(0, 8192));
	evilPropStr.push("ftp://localhost/"+magic);			

	// Long UNC	
	evilPropStr.push("\\\\"+mib.substring(0, 256));
	evilPropStr.push("\\\\"+mib.substring(0, 512));
	evilPropStr.push("\\\\"+mib.substring(0, 1024));
	evilPropStr.push("\\\\"+mib.substring(0, 8192));
	evilPropStr.push("\\\\localhost\\"+magic);	
	
	// Magic
	evilPropStr.push(magic);
	
	// Strings that often cause problems
	evilPropObj = new Array();
	
	evilPropObj.push( new Array() );
	evilPropObj.push( new Object() );
	evilPropObj.push( new Boolean() );
	evilPropObj.push( new Function() );
	evilPropObj.push( new Array(129) );
	evilPropObj.push( new Array(257) );
	evilPropObj.push( new Array(1025) );
	evilPropObj.push( new Array(8193) );
	evilPropObj.push( new Array(16385) );
	evilPropObj.push( new Array(32769) );
	evilPropObj.push( new Array(65537) );
	evilPropObj.push( evilPropNum );
	evilPropObj.push( evilPropStr );
	evilPropObj.push( document );
	evilPropObj.push( window );
}
function destroyEvilPropArgs() {
	evilPropNum = new Array();
	evilPropStr = new Array();
	evilPropObj = new Array();
}




// Evil method fuzzing values
var evilMethNum = new Array();
var evilMethStr = new Array();
var evilMethObj = new Array();

// Max argument count for thorough mode
var evilMethSlowMax = 3;
var evilMethSlowMin = 2;

function createEvilMethArgs(argc) {

	if (argc <= evilMethSlowMax && argc >= evilMethSlowMin)
		createEvilMethArgsSlow(argc);
	else
		createEvilMethArgsFast(argc);

	return(0);		
}

// Each item is used for all parameters in fast mode
function createEvilMethArgsFast(argc) {	
	// Integers that often cause problems
	var evilMethNumBase = new Array(
		0x100000000,
		 0x80000000,
		 0x40000000,
		 0x20000000,
		 0x10000000,
		 0x01000000,
		 0x00100000,
		 0x00010000,
		 0x00001000,
		 0x00000100,
		 0x00000010,
		 0x00000001
	);

	evilMethNum = new Array();
	for (var i in evilMethNumBase) {
		var d = evilMethNumBase[i];

		evilMethNum.push(d);
		evilMethNum.push(d+1);
		evilMethNum.push(d+2);	
		evilMethNum.push(d-1);	
		evilMethNum.push(d-2);	
		evilMethNum.push(d * -1);
		evilMethNum.push(d * -2);
	}
	
	
	// Strings that often cause problems
	
	evilMethStr = new Array();

	var mib = "A";
	while (mib.length <= (1024*1024)) mib += mib;
	
	evilMethStr.push(mib.substring(0, 1));

	// Incrementing sizes around 64b breaks
	for (var i = 0; i < 8192; i++) {
		if ( (i % 64 == 0) || ((i-1) % 62 == 0) || ((i+1) % 62 == 0) )
			evilMethStr.push(mib.substring(0, i));
	}
	
	evilMethStr.push(mib.substring(0, 1024));
	evilMethStr.push(mib.substring(0, 16384));
	evilMethStr.push(mib.substring(0, 32768));
	evilMethStr.push(mib);

	// Format strings
	evilMethStr.push("%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n");
	evilMethStr.push("%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s");

	// Long file paths
	evilMethStr.push("C:\\"+mib.substring(0, 256));
	evilMethStr.push("C:\\"+mib.substring(0, 512));
	evilMethStr.push("C:\\"+mib.substring(0, 1024));
	evilMethStr.push("C:\\"+mib.substring(0, 8192));
	evilMethStr.push("C:\\"+magic);

	// Long HTTP
	evilMethStr.push("http://"+mib.substring(0, 256));
	evilMethStr.push("http://"+mib.substring(0, 512));
	evilMethStr.push("http://"+mib.substring(0, 1024));
	evilMethStr.push("http://"+mib.substring(0, 8192));
	evilMethStr.push("http://localhost/");
	evilMethStr.push("http://localhost/"+magic);

	// Long FTP	
	evilMethStr.push("ftp://"+mib.substring(0, 256));
	evilMethStr.push("ftp://"+mib.substring(0, 512));
	evilMethStr.push("ftp://"+mib.substring(0, 1024));
	evilMethStr.push("ftp://"+mib.substring(0, 8192));
	evilMethStr.push("ftp://localhost/"+magic);			

	// Long UNC	
	evilMethStr.push("\\\\"+mib.substring(0, 256));
	evilMethStr.push("\\\\"+mib.substring(0, 512));
	evilMethStr.push("\\\\"+mib.substring(0, 1024));
	evilMethStr.push("\\\\"+mib.substring(0, 8192));
	evilMethStr.push("\\\\localhost\\"+magic);	
	
	// Magic
	evilMethStr.push(magic);
	
	// Strings that often cause problems
	evilMethObj = new Array();
	
	evilMethObj.push( new Array() );
	evilMethObj.push( new Object() );
	evilMethObj.push( new Boolean() );
	evilMethObj.push( new Function() );
	evilMethObj.push( new Array(129) );
	evilMethObj.push( new Array(257) );
	evilMethObj.push( new Array(1025) );
	evilMethObj.push( new Array(8193) );
	evilMethObj.push( new Array(16385) );
	evilMethObj.push( new Array(32769) );
	evilMethObj.push( new Array(65537) );
	evilMethObj.push( evilMethNum );
	evilMethObj.push( evilMethStr );
	evilMethObj.push( document );
	evilMethObj.push( window );
}

// Every combination of parameters is tested in slow mode
// This results in exponential keyspace growth!
function createEvilMethArgsSlow(argc) {	

	// Integers that often cause problems
	var evilMethNumBase = new Array();
	
	evilMethNumBase = new Array(
		0x100000000,
		 0x80000000,
		 0x00000100,
		 0x00000010,
		 0x00000001
	);

	evilMethNum = new Array();
	for (var i in evilMethNumBase) {
		var d = evilMethNumBase[i];
		evilMethNum.push(d);
		evilMethNum.push(d+1);	
		evilMethNum.push(d-1);	
		evilMethNum.push(d * -1);
	}
	
	
	// Strings that often cause problems
	
	evilMethStr = new Array();
	
	var mib = "A";
	while (mib.length <= (1024*1024)) mib += mib;
	
	evilMethStr.push(mib.substring(0, 1));
	evilMethStr.push(mib.substring(0, 1024));
	evilMethStr.push(mib.substring(0, 16384));
	evilMethStr.push(mib.substring(0, 32768));
	evilMethStr.push(mib);

	// Format strings
	evilMethStr.push("%n%n%n%n%n%s%s%s%s%s");

	// Long file paths
	evilMethStr.push("C:\\"+mib.substring(0, 8192));
	evilMethStr.push("C:\\"+magic);

	// Long HTTP
	evilMethStr.push("http://"+mib.substring(0, 8192));
	evilMethStr.push("http://localhost/"+magic);

	// Long FTP	
	evilMethStr.push("ftp://"+mib.substring(0, 8192));
	evilMethStr.push("ftp://localhost/"+magic);			

	// Long UNC	
	evilMethStr.push("\\\\"+mib.substring(0, 8192));
	evilMethStr.push("\\\\localhost\\"+magic);	
	
	// Magic
	evilMethStr.push(magic);
	
	// Strings that often cause problems
	evilMethObj = new Array();
	evilMethObj.push( new Function() );
	evilMethObj.push( new Array(65537) );
	evilMethObj.push( window );
	alert(evilMethObj[1]);
}

function destroyEvilMethArgs() {
	evilMethNum = new Array();
	evilMethStr = new Array();
	evilMethObj = new Array();
}

			
/*
 *
 * Utility functions
 *
 */

// Create hash tables for class names
var blclasses_hash = new Object;

function initBadClassHash(){
	for (var i in blclasses)
		blclasses_hash[blclasses[i].toUpperCase()]=true;
}

// Hash lookup
function isBadClass(cls) {
	cls = cls.toString().toUpperCase();
	return(blclasses_hash[cls.toUpperCase()] ? true : false);
}

// Linear search
function isBadMethod(cls, meth) {
	meth = meth.toString().toUpperCase();
	cls  = cls.toString().toUpperCase();
	
	for (var i in blmethods) {
		var c = i.toUpperCase();
		
		for (var x in blmethods[i]) {
			if ( (c == 'ALL' || c == cls) && (blmethods[i][x].toUpperCase() == meth) )
			   	return(true);
		}
	}

	return(false);
}

// Linear search
function isBadProperty(cls, prop) {
	prop = prop.toString().toUpperCase();
	cls  = cls.toString().toUpperCase();
	
	for (var i in blproperties) {
		var c = i.toUpperCase();
		
		for (var x in blproperties[i]) {
			if ( (c == 'ALL' || c == cls) && (blproperties[i][x].toUpperCase() == prop) )
			   	return(true);
		}
	}

	return(false);
}
