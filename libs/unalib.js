// modulo de ejemplo.

module.exports = {

    // Función para sanitizar texto y prevenir XSS
    sanitizeText: function(text) {
      if (typeof text !== 'string') {
        return '';
      }
      
      // Escapar caracteres HTML peligrosos
      return text
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#x27;')
        .replace(/\//g, '&#x2F;');
    },

    // Función para detectar contenido malicioso
    containsMaliciousContent: function(text) {
      if (typeof text !== 'string') {
        return false;
      }
      
      // Patrones de contenido malicioso mejorados
      var maliciousPatterns = [
        /<script[\s\S]*?<\/script>/gi,  // Script tags con cualquier contenido
        /<script\b/gi,                  // Cualquier apertura de script tag
        /javascript:/gi,
        /vbscript:/gi,
        /on\w+\s*=/gi,                  // Event handlers (onclick, onload, etc.)
        /<iframe\b/gi,
        /<object\b/gi,
        /<embed\b/gi,
        /<link\b/gi,
        /<meta\b/gi,
        /data:\s*text\/html/gi,         // Data URLs con HTML
        /data:\s*application\/javascript/gi,
        /file:/gi,
        /<form\b/gi,
        /eval\s*\(/gi,
        /expression\s*\(/gi,
        /alert\s*\(/gi,                 // Funciones de alerta
        /confirm\s*\(/gi,
        /prompt\s*\(/gi,
        /document\.write/gi,
        /innerHTML\s*=/gi,
        /outerHTML\s*=/gi
      ];
      
      for (var i = 0; i < maliciousPatterns.length; i++) {
        if (maliciousPatterns[i].test(text)) {
          console.log('Contenido malicioso detectado con patrón:', maliciousPatterns[i].toString());
          return true;
        }
      }
      
      return false;
    },

    // Función para validar URLs seguras
    isValidSecureUrl: function(url) {
      if (typeof url !== 'string' || url.length === 0) {
        return false;
      }
      
      // Solo permitir HTTP y HTTPS
      if (!/^https?:\/\//i.test(url)) {
        return false;
      }
      
      // Lista de dominios seguros para contenido multimedia
      var safeDomains = [
        'youtube.com',
        'youtu.be',
        'imgur.com',
        'i.imgur.com',
        'media.giphy.com',
        'giphy.com',
        'unsplash.com',
        'images.unsplash.com',
        'pixabay.com',
        'pexels.com',
        'wikimedia.org',
        'upload.wikimedia.org',
        'images.google.com',
        'lh3.googleusercontent.com',
        'lh4.googleusercontent.com',
        'lh5.googleusercontent.com',
        'lh6.googleusercontent.com',
        'googleusercontent.com',
        'storage.googleapis.com',
        'drive.google.com',
        'imgs.search.brave.com',
        'brave.com',
        'search.brave.com'
      ];
      
      try {
        var urlObj = new URL(url);
        var hostname = urlObj.hostname.toLowerCase();
        
        // Verificar si es un dominio seguro conocido
        for (var i = 0; i < safeDomains.length; i++) {
          if (hostname === safeDomains[i] || hostname.endsWith('.' + safeDomains[i])) {
            return true;
          }
        }
        
        // Si no está en la lista de dominios seguros, verificar que sea una URL directa a archivo multimedia
        var pathname = urlObj.pathname.toLowerCase();
        var validExtensions = /\.(jpg|jpeg|png|gif|bmp|webp|svg|mp4|avi|mov|wmv|flv|webm|mkv|m4v|3gp|ogv)$/i;
        
        return validExtensions.test(pathname);
        
      } catch (e) {
        console.log('Error validando URL:', e);
        return false;
      }
    },


    // logica que valida si un telefono esta correcto...
    is_valid_phone: function (phone) {
      // inicializacion lazy
      var isValid = false;
      // expresion regular copiada de StackOverflow
      var re = /^[+]*[(]{0,1}[0-9]{1,4}[)]{0,1}[-\s\./0-9]*$/i;
  
      // validacion Regex
      try {
        isValid = re.test(phone);
      } catch (e) {
        console.log(e);
      } finally {
          return isValid;
      }
      // fin del try-catch block
    },
  
    is_valid_url_image: function (url) {
      // Primero verificar seguridad básica
      if (!this.isValidSecureUrl(url)) {
        return false;
      }
      
      try {
        var urlObj = new URL(url);
        var hostname = urlObj.hostname.toLowerCase();
        
        // URLs especiales que no siempre terminan en extensión de imagen
        if (hostname.indexOf('googleusercontent.com') !== -1 || 
            hostname === 'images.google.com' ||
            hostname === 'drive.google.com' ||
            hostname === 'imgs.search.brave.com' ||
            hostname.indexOf('brave.com') !== -1) {
          return true;
        }
        
        // Validación por extensión para otros dominios
        var re = /^https?:\/\/.*\.(jpg|jpeg|png|gif|bmp|webp|svg|ico|tiff|tif)(\?.*)?$/i;
        return re.test(url);
        
      } catch (e) {
        console.log('Error validando imagen URL:', e);
        return false;
      }
    },
  
    is_valid_yt_video: function (url) {
      try {
        // Primero verificar que sea una URL válida
        var urlObj = new URL(url);
        var hostname = urlObj.hostname.toLowerCase();
        
        // Verificar que sea de YouTube
        if (hostname !== 'www.youtube.com' && 
            hostname !== 'youtube.com' && 
            hostname !== 'youtu.be' &&
            hostname !== 'm.youtube.com') {
          return false;
        }
        
        // Expresión regular mejorada para YouTube
        var re = /^(?:https?:\/\/)?(?:www\.|m\.)?(?:youtu\.be\/|youtube\.com\/(?:embed\/|v\/|watch\?v=|watch\?.+&v=))([\w-]{11})(?:\S+)?$/i;
        
        return re.test(url);
        
      } catch (e) {
        console.log('Error validando YouTube URL:', e);
        return false;
      }
    },

    is_valid_video_file: function (url) {
      // Primero verificar seguridad básica
      if (!this.isValidSecureUrl(url)) {
        return false;
      }
      
      // inicializacion lazy
      var isValid = false;
      // expresion regular para detectar archivos de video directos
      var re = /^https?:\/\/.*\.(mp4|avi|mov|wmv|flv|webm|mkv|m4v|3gp|ogv)(\?.*)?$/i;
  
      // validacion Regex
      try {
        isValid = re.test(url);
      } catch (e) {
        console.log(e);
      } finally {
          return isValid;
      }
    },
  
    getYTVideoId: function(url){
      try {
        // Mejorar la extracción del ID de YouTube
        var match = url.match(/(?:https?:\/\/)?(?:www\.|m\.)?(?:youtu\.be\/|youtube\.com\/(?:embed\/|v\/|watch\?v=|watch\?.+&v=))([\w-]{11})/i);
        return match ? match[1] : null;
      } catch (e) {
        console.log('Error extrayendo ID de YouTube:', e);
        return null;
      }
    },
  
    getEmbeddedCode: function (url){
      var id = this.getYTVideoId(url);
      if (!id) {
        console.log('No se pudo extraer ID de YouTube de:', url);
        return 'Error: URL de YouTube inválida';
      }
      var code = '<iframe width="560" height="315" src="https://www.youtube.com/embed/'+id+ '" frameborder="0" allow="accelerometer; autoplay; encrypted-media; gyroscope; picture-in-picture" allowfullscreen></iframe>';
      return code;
    },

    getVideoTag: function(url){
      var tag = '<video controls>' +
                '<source src="' + url + '" type="video/mp4">' +
                'Su navegador no soporta el elemento video.' +
                '</video>';
      return tag;
    },
  
    getImageTag: function(url){
      var tag = '<img src="'+url+'" alt="Imagen compartida" loading="lazy">';
      return tag;
    },
  
    validateMessage: function(msg){
      // Handle invalid input
      if (!msg || typeof msg !== 'string') {
        return JSON.stringify({ mensaje: '' });
      }

      try {
        var obj = JSON.parse(msg);
        
        // Validar que los campos requeridos existan
        if (!obj.mensaje || typeof obj.mensaje !== 'string') {
          console.log('Mensaje inválido o vacío');
          return JSON.stringify({ mensaje: '' });
        }
        
        // Sanitizar el nombre del usuario
        if (obj.nombre) {
          obj.nombre = this.sanitizeText(obj.nombre);
        }
        
        // Verificar contenido malicioso en el mensaje
        if (this.containsMaliciousContent(obj.mensaje)) {
          console.log('⚠️ CONTENIDO MALICIOSO BLOQUEADO:', obj.mensaje);
          obj.mensaje = '🚫 MENSAJE BLOQUEADO: Se detectó contenido malicioso y fue bloqueado por seguridad.';
          return JSON.stringify(obj);
        }
        
        // Procesar URLs de contenido multimedia
        if (this.is_valid_url_image(obj.mensaje)) {
          console.log("Es una imagen segura!");
          obj.mensaje = this.getImageTag(obj.mensaje);
        }
        else if (this.is_valid_yt_video(obj.mensaje)) {
          console.log("Es un video de YouTube seguro!");
          obj.mensaje = this.getEmbeddedCode(obj.mensaje);
        }
        else if (this.is_valid_video_file(obj.mensaje)) {
          console.log("Es un archivo de video seguro!");
          obj.mensaje = this.getVideoTag(obj.mensaje);
        }
        else {
          // Para texto normal, sanitizar para prevenir XSS
          console.log("Es un texto - aplicando sanitización");
          obj.mensaje = this.sanitizeText(obj.mensaje);
          
          // Limitar longitud del mensaje
          if (obj.mensaje.length > 1000) {
            obj.mensaje = obj.mensaje.substring(0, 1000) + '... (mensaje truncado)';
          }
        }
        
        // Validar y sanitizar el color si existe
        if (obj.color) {
          // Solo permitir colores hexadecimales válidos
          if (!/^#[0-9A-Fa-f]{6}$/.test(obj.color)) {
            obj.color = '#000000'; // Color por defecto si es inválido
          }
        }
        
        return JSON.stringify(obj);
        
      } catch (e) {
        console.log('Error processing message:', e);
        // En caso de error, devolver un mensaje sanitizado
        return JSON.stringify({ 
          mensaje: this.sanitizeText(msg.toString().substring(0, 100)),
          nombre: 'Usuario',
          color: '#000000'
        });
      }
    }
  
  
  
    
    
  
  // fin del modulo
  };
  