/**
 * Pruebas Unitarias para UNA Lib - Sistema de Chat Seguro
 * Cubre validación de URLs de imágenes, videos y prevención de XSS
 */

// Importar la librería a probar
var unaLib = require('../libs/unalib');

// Variables para llevar el control de las pruebas
var totalTests = 0;
var passedTests = 0;
var failedTests = 0;

/**
 * Función auxiliar para ejecutar pruebas
 */
function runTest(testName, testFunction) {
    totalTests++;
    console.log(`\n🔍 Ejecutando: ${testName}`);
    
    try {
        var result = testFunction();
        if (result) {
            passedTests++;
            console.log(`✅ PASÓ: ${testName}`);
        } else {
            failedTests++;
            console.log(`❌ FALLÓ: ${testName}`);
        }
    } catch (error) {
        failedTests++;
        console.log(`❌ ERROR en ${testName}: ${error.message}`);
    }
}

/**
 * Función auxiliar para verificar igualdad
 */
function assertEqual(actual, expected, message) {
    if (actual === expected) {
        return true;
    } else {
        console.log(`   💥 ${message || 'Assertion falló'}`);
        console.log(`   Esperado: ${expected}`);
        console.log(`   Obtenido: ${actual}`);
        return false;
    }
}

/**
 * Función auxiliar para verificar que contiene
 */
function assertContains(text, substring, message) {
    if (text && text.indexOf(substring) !== -1) {
        return true;
    } else {
        console.log(`   💥 ${message || 'No contiene el substring esperado'}`);
        console.log(`   Texto: ${text}`);
        console.log(`   Buscando: ${substring}`);
        return false;
    }
}

console.log('🚀 INICIANDO PRUEBAS UNITARIAS PARA UNA LIB\n');
console.log('='.repeat(60));

// ===============================================
// PRUEBAS DE VALIDACIÓN DE URLs DE IMÁGENES
// ===============================================
console.log('\n📸 PRUEBAS DE VALIDACIÓN DE URLs DE IMÁGENES');
console.log('-'.repeat(50));

runTest('Imagen JPG válida de Imgur', function() {
    var url = 'https://i.imgur.com/test.jpg';
    return assertEqual(unaLib.is_valid_url_image(url), true, 'Debería validar imagen JPG de Imgur');
});

runTest('Imagen PNG válida de Wikimedia', function() {
    var url = 'https://upload.wikimedia.org/image.png';
    return assertEqual(unaLib.is_valid_url_image(url), true, 'Debería validar imagen PNG de Wikimedia');
});

runTest('Imagen GIF válida de Giphy', function() {
    var url = 'https://media.giphy.com/media/test/giphy.gif';
    return assertEqual(unaLib.is_valid_url_image(url), true, 'Debería validar GIF de Giphy');
});

runTest('Imagen WebP con parámetros', function() {
    var url = 'https://images.unsplash.com/photo.webp?width=400&height=300';
    return assertEqual(unaLib.is_valid_url_image(url), true, 'Debería validar WebP con parámetros');
});

runTest('URL maliciosa con extensión de imagen', function() {
    var url = 'javascript:alert("hack").jpg';
    return assertEqual(unaLib.is_valid_url_image(url), false, 'No debería validar URL con javascript');
});

runTest('Dominio no seguro con imagen', function() {
    var url = 'http://malicious-site.com/image.jpg';
    return assertEqual(unaLib.is_valid_url_image(url), false, 'No debería validar dominio no seguro');
});

runTest('Protocolo FTP con imagen', function() {
    var url = 'ftp://server.com/image.png';
    return assertEqual(unaLib.is_valid_url_image(url), false, 'No debería validar protocolo FTP');
});

// ===============================================
// PRUEBAS DE VALIDACIÓN DE URLs DE VIDEOS
// ===============================================
console.log('\n🎥 PRUEBAS DE VALIDACIÓN DE URLs DE VIDEOS');
console.log('-'.repeat(50));

runTest('Video de YouTube válido (watch)', function() {
    var url = 'https://www.youtube.com/watch?v=dQw4w9WgXcQ';
    return assertEqual(unaLib.is_valid_yt_video(url), true, 'Debería validar URL de YouTube');
});

runTest('Video de YouTube válido (youtu.be)', function() {
    var url = 'https://youtu.be/dQw4w9WgXcQ';
    return assertEqual(unaLib.is_valid_yt_video(url), true, 'Debería validar URL corta de YouTube');
});

runTest('Video de YouTube sin HTTPS', function() {
    var url = 'http://www.youtube.com/watch?v=dQw4w9WgXcQ';
    return assertEqual(unaLib.is_valid_yt_video(url), true, 'Debería validar YouTube sin HTTPS');
});

runTest('Video MP4 directo válido', function() {
    var url = 'https://sample-videos.com/zip/10/mp4/SampleVideo_1280x720_1mb.mp4';
    return assertEqual(unaLib.is_valid_video_file(url), true, 'Debería validar video MP4 directo');
});

runTest('Video WebM directo válido', function() {
    var url = 'https://file-examples.com/storage/fe68c30c7d66dda19fa93e1/2017/10/file_example_WEBM_480_900KB.webm';
    return assertEqual(unaLib.is_valid_video_file(url), true, 'Debería validar video WebM directo');
});

runTest('URL maliciosa con extensión de video', function() {
    var url = 'javascript:alert("hack").mp4';
    return assertEqual(unaLib.is_valid_video_file(url), false, 'No debería validar URL maliciosa con extensión MP4');
});

runTest('Video de dominio no seguro', function() {
    var url = 'http://untrusted-site.com/video.mp4';
    return assertEqual(unaLib.is_valid_video_file(url), false, 'No debería validar video de dominio no seguro');
});

// ===============================================
// PRUEBAS DE PREVENCIÓN DE INYECCIÓN DE SCRIPTS
// ===============================================
console.log('\n🛡️ PRUEBAS DE PREVENCIÓN DE INYECCIÓN DE SCRIPTS (XSS)');
console.log('-'.repeat(50));

runTest('Detectar script tag básico', function() {
    var maliciousContent = '<script>alert("XSS")</script>';
    return assertEqual(unaLib.containsMaliciousContent(maliciousContent), true, 'Debería detectar script tag');
});

runTest('Detectar javascript: protocol', function() {
    var maliciousContent = 'javascript:alert("hack")';
    return assertEqual(unaLib.containsMaliciousContent(maliciousContent), true, 'Debería detectar javascript: protocol');
});

runTest('Detectar event handlers', function() {
    var maliciousContent = '<img onload="malicious()" src="x">';
    return assertEqual(unaLib.containsMaliciousContent(maliciousContent), true, 'Debería detectar event handlers');
});

runTest('Detectar iframe malicioso', function() {
    var maliciousContent = '<iframe src="http://evil.com"></iframe>';
    return assertEqual(unaLib.containsMaliciousContent(maliciousContent), true, 'Debería detectar iframe');
});

runTest('Detectar data: protocol', function() {
    var maliciousContent = 'data:text/html,<script>alert("XSS")</script>';
    return assertEqual(unaLib.containsMaliciousContent(maliciousContent), true, 'Debería detectar data: protocol');
});

runTest('Texto normal sin contenido malicioso', function() {
    var normalContent = 'Este es un mensaje normal del chat';
    return assertEqual(unaLib.containsMaliciousContent(normalContent), false, 'No debería detectar contenido normal como malicioso');
});

runTest('URL de imagen normal', function() {
    var imageUrl = 'https://i.imgur.com/image.jpg';
    return assertEqual(unaLib.containsMaliciousContent(imageUrl), false, 'No debería detectar URL de imagen como maliciosa');
});

// ===============================================
// PRUEBAS DE SANITIZACIÓN DE CONTENIDO
// ===============================================
console.log('\n🧹 PRUEBAS DE SANITIZACIÓN DE CONTENIDO HTML');
console.log('-'.repeat(50));

runTest('Sanitizar caracteres HTML básicos', function() {
    var input = '<div>Hola & "mundo"</div>';
    var expected = '&lt;div&gt;Hola &amp; &quot;mundo&quot;&lt;&#x2F;div&gt;';
    var result = unaLib.sanitizeText(input);
    return assertEqual(result, expected, 'Debería escapar caracteres HTML');
});

runTest('Sanitizar script tag', function() {
    var input = '<script>alert("XSS")</script>';
    var result = unaLib.sanitizeText(input);
    return assertContains(result, '&lt;script&gt;', 'Debería escapar script tags');
});

runTest('Sanitizar comillas simples y dobles', function() {
    var input = "Texto con 'comillas' y \"dobles\"";
    var result = unaLib.sanitizeText(input);
    return assertContains(result, '&#x27;', 'Debería escapar comillas simples') && 
           assertContains(result, '&quot;', 'Debería escapar comillas dobles');
});

runTest('Texto vacío o null', function() {
    var result1 = unaLib.sanitizeText('');
    var result2 = unaLib.sanitizeText(null);
    var result3 = unaLib.sanitizeText(undefined);
    return assertEqual(result1, '', 'String vacío debería retornar vacío') &&
           assertEqual(result2, '', 'null debería retornar vacío') &&
           assertEqual(result3, '', 'undefined debería retornar vacío');
});

// ===============================================
// PRUEBAS DE VALIDACIÓN COMPLETA DE MENSAJES
// ===============================================
console.log('\n💬 PRUEBAS DE VALIDACIÓN COMPLETA DE MENSAJES');
console.log('-'.repeat(50));

runTest('Mensaje normal válido', function() {
    var input = JSON.stringify({nombre: 'Usuario', mensaje: 'Hola mundo', color: '#ff0000'});
    var result = JSON.parse(unaLib.validateMessage(input));
    return assertEqual(result.nombre, 'Usuario', 'Nombre debería mantenerse') &&
           assertEqual(result.mensaje, 'Hola mundo', 'Mensaje normal debería mantenerse') &&
           assertEqual(result.color, '#ff0000', 'Color válido debería mantenerse');
});

runTest('Mensaje con contenido malicioso', function() {
    var input = JSON.stringify({nombre: 'Hacker', mensaje: '<script>alert("XSS")</script>', color: '#000000'});
    var result = JSON.parse(unaLib.validateMessage(input));
    return assertEqual(result.mensaje, 'Mensaje bloqueado por razones de seguridad', 'Contenido malicioso debería ser bloqueado');
});

runTest('Mensaje con URL de imagen válida', function() {
    var input = JSON.stringify({nombre: 'Usuario', mensaje: 'https://i.imgur.com/test.jpg', color: '#00ff00'});
    var result = JSON.parse(unaLib.validateMessage(input));
    return assertContains(result.mensaje, '<img', 'URL de imagen debería generar tag img');
});

runTest('Mensaje con URL de YouTube válida', function() {
    var input = JSON.stringify({nombre: 'Usuario', mensaje: 'https://www.youtube.com/watch?v=test', color: '#0000ff'});
    var result = JSON.parse(unaLib.validateMessage(input));
    return assertContains(result.mensaje, '<iframe', 'URL de YouTube debería generar iframe');
});

runTest('Mensaje con color inválido', function() {
    var input = JSON.stringify({nombre: 'Usuario', mensaje: 'Hola', color: 'invalid-color'});
    var result = JSON.parse(unaLib.validateMessage(input));
    return assertEqual(result.color, '#000000', 'Color inválido debería ser reemplazado por defecto');
});

runTest('Mensaje muy largo', function() {
    var longMessage = 'A'.repeat(1500);
    var input = JSON.stringify({nombre: 'Usuario', mensaje: longMessage, color: '#ffffff'});
    var result = JSON.parse(unaLib.validateMessage(input));
    return assertEqual(result.mensaje.length <= 1000, true, 'Mensaje largo debería ser truncado') &&
           assertContains(result.mensaje, 'truncado', 'Debería indicar que fue truncado');
});

runTest('JSON inválido', function() {
    var input = 'esto no es JSON válido';
    var result = JSON.parse(unaLib.validateMessage(input));
    return assertEqual(result.nombre, 'Usuario', 'JSON inválido debería tener valores por defecto');
});

// ===============================================
// PRUEBAS DE URLs SEGURAS
// ===============================================
console.log('\n🔒 PRUEBAS DE VALIDACIÓN DE URLs SEGURAS');
console.log('-'.repeat(50));

runTest('Dominio seguro conocido', function() {
    var url = 'https://i.imgur.com/image.jpg';
    return assertEqual(unaLib.isValidSecureUrl(url), true, 'Imgur debería ser considerado seguro');
});

runTest('Protocolo HTTPS válido', function() {
    var url = 'https://example.com/file.jpg';
    return assertEqual(unaLib.isValidSecureUrl(url), true, 'HTTPS con extensión válida debería ser seguro');
});

runTest('Protocolo HTTP válido', function() {
    var url = 'http://example.com/file.mp4';
    return assertEqual(unaLib.isValidSecureUrl(url), true, 'HTTP con extensión válida debería ser seguro');
});

runTest('Protocolo javascript', function() {
    var url = 'javascript:alert("hack")';
    return assertEqual(unaLib.isValidSecureUrl(url), false, 'javascript: no debería ser considerado seguro');
});

runTest('Protocolo data', function() {
    var url = 'data:image/png;base64,iVBORw0KGgoA';
    return assertEqual(unaLib.isValidSecureUrl(url), false, 'data: no debería ser considerado seguro');
});

runTest('URL sin protocolo', function() {
    var url = 'example.com/image.jpg';
    return assertEqual(unaLib.isValidSecureUrl(url), false, 'URL sin protocolo no debería ser válida');
});

// ===============================================
// RESUMEN DE RESULTADOS
// ===============================================
console.log('\n' + '='.repeat(60));
console.log('📊 RESUMEN DE PRUEBAS UNITARIAS');
console.log('='.repeat(60));
console.log(`📈 Total de pruebas ejecutadas: ${totalTests}`);
console.log(`✅ Pruebas exitosas: ${passedTests}`);
console.log(`❌ Pruebas fallidas: ${failedTests}`);
console.log(`📊 Porcentaje de éxito: ${((passedTests/totalTests)*100).toFixed(1)}%`);

if (failedTests === 0) {
    console.log('\n🎉 ¡TODAS LAS PRUEBAS PASARON EXITOSAMENTE!');
    console.log('✅ El sistema de validación de seguridad está funcionando correctamente.');
} else {
    console.log(`\n⚠️ ${failedTests} prueba(s) fallaron. Revisar implementación.`);
}

console.log('\n🛡️ Validaciones de seguridad verificadas:');
console.log('   • Prevención de inyección XSS');
console.log('   • Sanitización de contenido HTML');  
console.log('   • Validación de URLs seguras');
console.log('   • Validación de imágenes');
console.log('   • Validación de videos');
console.log('   • Manejo robusto de errores');

// Exportar resultado para uso en CI/CD
process.exit(failedTests === 0 ? 0 : 1);