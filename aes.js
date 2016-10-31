var plainText = '';
var iv = '';
var key = '';

var bitsPlainText, bytesPlainText;
var bitsIv, bytesIv;
var bitsKey, bytesKey;

var originalEncryptedBits;
var newEncryptedBits;

var iterations;

var randomString;

//Hace el flip de un bit en la posicion que se le indica
var flipBit = function( string, position ){

  var newValue;

  if( string[position] == 0 ){
    newValue = 1;
  }else{
    newValue = 0;
  }

  var result = string.substr(0, position) + newValue + string.substr(position + 1);
  return result;

}

//Conversores
var byteArrayToBinary = function( array ){

  var result = '';

  array.forEach( function(item){
    result += decimalToBinary(item);
  })

  return result;

}

var decimalToBinary = function( number ){

  var result = parseInt(number, 10).toString(2);

  //La conversion se olvida de los 0 a la izquierda, si hay que ponerlos para llegar a los 8 bits los añadimos
  var padding = 8 - result.toString().length;
  if ( padding > 0 ){

    var toAdd = '';
    for( var i = 0; i < padding; i++ ){
      toAdd += '0';
    }
    result = toAdd.concat(result);

  }

  return result;
}

var stringToBits = function( theString ){

  var result = ''
  for (var i = 0; i < theString.length; i++) {
    result += theString[i].charCodeAt(0).toString(2);
  }
  return result;

}

var bin2array = function(bin){

  var array = [];

  if( bin.length == 128 ){

    array = bin.match(/.{1,8}/g);

    array.forEach( function(element, index){
      array[index] = bin2dec(element);
    });

  }

  return array;

}

var bin2dec = function(bin){

  return parseInt(parseInt(bin,2).toString(10),10);

}

var dec2bin = function(dec){
  return (dec >>> 0).toString(2);
}

var convertStrings = function(){

  bytesPlainText = aesjs.util.convertStringToBytes(plainText);
  bytesIv = aesjs.util.convertStringToBytes(iv);
  bytesKey = aesjs.util.convertStringToBytes(key);

  bitsPlainText = byteArrayToBinary( bytesPlainText );
  bitsIv = byteArrayToBinary( bytesIv );
  bitsKey = byteArrayToBinary( bytesKey );

}

//Calcula la distancia de hamming de un string respecto a un array
var calculateValues = function( bits, array){

  var result = [];
  var len = bits.length;

  array.forEach( function(element,index){

    var distance = 0;

    if( len === element.length ){

      for( var i = 0; i<len; i++ ){

        if( bits[i] != element[i] ){
          distance++;
        }

      }

    }else{
      distance = 'a';
    }

    result.push(distance);

  });

  return result;

}

//calcula la media
var calculateMean = function( array ){

  var mean = 0;

  for( var i = 0; i < array.length; i++ ){
    mean += array[i];
  }

  mean = mean / array.length;
  return mean;

}

//calcula la desviacion tipica
var standardDeviation = function(values){
  var avg = average(values);

  var squareDiffs = values.map(function(value){
    var diff = value - avg;
    var sqrDiff = diff * diff;
    return sqrDiff;
  });

  var avgSquareDiff = average(squareDiffs);

  var stdDev = Math.sqrt(avgSquareDiff);
  return stdDev;
}

var average = function(data){
  var sum = data.reduce(function(sum, value){
    return sum + value;
  }, 0);

  var avg = sum / data.length;
  return avg;
}

//calcula la moda
var mode = function(array){

  if(array.length == 0)
  	return null;
  var modeMap = {};
  var maxEl = array[0], maxCount = 1;
  for(var i = 0; i < array.length; i++)
  {
  	var el = array[i];
  	if(modeMap[el] == null)
  		modeMap[el] = 1;
  	else
  		modeMap[el]++;
  	if(modeMap[el] > maxCount)
  	{
  		maxEl = el;
  		maxCount = modeMap[el];
  	}
  }
  return maxEl;
}

//Realiza todas las operaciones necesarias (cifrado, generacion de cifrados tras modificar la cadena de bits, etc).
var work = function(randomString){

  plainText = '';
  iv = '';
  key = '';

  if( randomString.length < 48 ){
    return;
  }

  for( var i = 0; i < 48; i++ ){

    if( i < 16 ){
      plainText += randomString[i];
    }else if ( i < 32) {
      iv += randomString[i];
    }else{
      key += randomString[i];
    }

  }

  convertStrings();

  var aesCbc = new aesjs.ModeOfOperation.cbc(bytesKey, bytesIv);
  var encryptedBytes = aesCbc.encrypt(bytesPlainText);

  originalEncryptedBits = byteArrayToBinary(encryptedBytes);
  console.log('original encriptado', originalEncryptedBits);

  //Vamos a generar aproximadamente 100 * 3 = 300 pruebas. Si digo aproximadamente es porque vamos a solicitar 300 posiciones aleatorias entre 0 y 127.
  //Al generarse de manera aleatoria, es posible que ciertas posiciones se repitan, por lo tanto las ignoraremos
  var arrayText = new Uint32Array(100);
  var arrayIv = new Uint32Array(100);
  var arrayKey = new Uint32Array(100);

  window.crypto.getRandomValues(arrayText);
  window.crypto.getRandomValues(arrayIv);
  window.crypto.getRandomValues(arrayKey);

  var positionsText = [];
  var positionsIv = [];
  var positionsKey = [];
  var modificatedTexts = [];
  var modificatedIvs = [];
  var modificatedKeys = [];
  var modificatedTotal = [];

  for ( var i = 0; i < 100; i++ ) {

    var num = parseInt( (arrayText[i]/(0xffffffff + 1) ) * 127, 10);
    if( positionsText.indexOf( num ) == -1 ){
      positionsText.push( num );
    }

    num = parseInt( (arrayIv[i]/(0xffffffff + 1) ) * 127, 10)
    if( positionsIv.indexOf( num ) == -1 ){
      positionsIv.push( num );
    }

    num = parseInt( (arrayKey[i]/(0xffffffff + 1) ) * 127, 10)
    if( positionsKey.indexOf( num ) == -1 ){
      positionsKey.push( num );
    }

  }

  positionsText.forEach( function(element){

    var flipped = flipBit(bitsPlainText, element);

    var aesCbc = new aesjs.ModeOfOperation.cbc(bytesKey, bytesIv);
    var encryptedBytes = aesCbc.encrypt( bin2array(flipped) );
    var newEncryptedBits = byteArrayToBinary(encryptedBytes);

    modificatedTexts.push( newEncryptedBits );
    modificatedTotal.push( newEncryptedBits );

  });

  positionsIv.forEach( function(element){

    var flipped = flipBit(bitsIv, element);

    var aesCbc = new aesjs.ModeOfOperation.cbc(bytesKey, bin2array(flipped));
    var encryptedBytes = aesCbc.encrypt( bytesPlainText );
    var newEncryptedBits = byteArrayToBinary(encryptedBytes);

    modificatedIvs.push( newEncryptedBits );
    modificatedTotal.push( newEncryptedBits );

  });

  positionsKey.forEach( function(element){

    var flipped = flipBit(bitsKey, element);

    var aesCbc = new aesjs.ModeOfOperation.cbc(bin2array(flipped), bytesIv);
    var encryptedBytes = aesCbc.encrypt( bytesPlainText );
    var newEncryptedBits = byteArrayToBinary(encryptedBytes);

    modificatedKeys.push( newEncryptedBits );
    modificatedTotal.push( newEncryptedBits );

  });

  var hammingTexts = calculateValues(originalEncryptedBits, modificatedTexts);
  var hammingIvs = calculateValues(originalEncryptedBits, modificatedIvs);
  var hammingKeys = calculateValues(originalEncryptedBits, modificatedKeys);
  var hammingTotal = calculateValues(originalEncryptedBits, modificatedTotal);

  /*$('.mean').text( calculateMean(hammingTotal) );
  $('.std').text( standardDeviation(hammingTotal) );
  $('.mode').text( mode(hammingTotal) );*/

  return hammingTotal;
  //console.log(hammingTexts,hammingIvs,hammingKeys);
  //console.log(positionsText,positionsIv,positionsKey);
  //console.log(modificatedTexts,modificatedIvs,modificatedKeys);
  //console.log(standardDeviation(hammingTotal), mode(hammingTotal));
  //console.log(calculateMean(hammingTexts),calculateMean(hammingIvs),calculateMean(hammingKeys));
  //console.log(hammingTotal, calculateMean(hammingTotal), mode(hammingTotal));

}

//Recibe los argumentos del usuario y muestra al usuario los resultados al terminar la ejecucion
var startApp = function(){

  plainText = '';
  iv = '';
  key = '';

  randomString = $('#string').val();
  iterations = parseInt( $('#iterations').val() ) || 100;

  randomString = randomString.split(';');
  console.log(randomString);

  var hammingFinal = [];

  randomString.forEach( function(element) {

    hammingFinal = hammingFinal.concat( work( element ) );

  });

  $('.nStrings').text( randomString.length );
  $('.totalIterations').text( hammingFinal.length );
  $('.mean').text( calculateMean(hammingFinal) );
  $('.std').text( standardDeviation(hammingFinal) );
  $('.mode').text( mode(hammingFinal) );
  $('.incertidumbre').text( standardDeviation(hammingFinal) / Math.sqrt( hammingFinal.length ) )

  var data = [
    {
      x: hammingFinal,
      type: 'histogram',
        marker: {
      color: 'rgba(100,250,100,0.7)',
      },
    }
  ];
  Plotly.newPlot('canvas', data);


}
