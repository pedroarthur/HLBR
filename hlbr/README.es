HOGWASH LIGHT BR

INSTALACIÓN
------------

Para instalar HLBR, siga los siguientes pasos:

1. Luego de extraer el tarball, ejecute el comando "# ./configure".

2. Ejecute el comando "# make". Serán necesario tener ya instalados los 
   compiladores para C (gcc) y C++.

3. Ejecute el comando "# make installes" para instalar HLBR con la versión
   en español del archivo de configuración (los comentarios en el archivo
   estarán en español). To install the file with comments in english, run 
   the command "# make installen". To install the file with comments in 
   brazilian portuguese, run the command "# make install".

4. Edite el archivo /etc/hlbr.config según sea necesario.

5. Compile un nuevo kernel eliminando toda la pila de protocolos TCP/IP o
   configure las interfaces de red en el rango 127.0.0.0 (no use 127.0.0.1,
   ya que ésta ya está en uso por la interfaz de loopback). Use direcciones
   como 127.0.0.2, 127.0.0.3 y similares. Recomendamos la segunda opción 
   en lugar de recompilar el kernel. Esto facilitará la instalación y le 
   permitirá utilizar otros programas para auditar el tráfico como iptraf,
   TCPdump, y otros, ya que aún existirá soporte IP (capa 3). Los datos 
   fluirán por la capa 2 (enlace), pero seguirán siendo visibles en la 
   capa 3 (red).

6. Para probar, ir al directorio /etc/hlbr y ejecutar:

    # hlbr -c hlbr.config -r empty.rules

	El daemon HLBR debería estar cargado.

7. Detener el servicio con Ctrl-C.

8. Cambiar los archivos de reglas (*.rules) dentro de /etc/hlbr/rules según
   sea necesario. Esos archivos serán cargados por /etc/hlbr/hlbr.rules.

9. Para ejecutar HLBR, emplee:

    # hlbr -c hlbr.config -r hlbr.rules &
    
    o
    
    # /etc/init.d/hlbr start

10. Los logs (bitácoras) pueden encontrarse en /var/log/hlbr, a menos que 
    usted haya cambiado esta ubicación en el archivo de configuración
    (/etc/hlbr/hlbr.config) o use la opción -l (escriba "hlbr" para ver las
    opciones).

11. Para detenerlo, ejecute:

    # killall hlbr
    
    o
    
    # /etc/init.d/hlbr stop

12. Para desinstalar, emplee "# make uninstall". ADVERTENCIA: todos los 
    archivos de configuración y logs serán eliminados.

13. Para "limpiar" le directorio del código fuente (como si nunca hubiera 
    sido compilado), emplee "# make clean".

14. Para más información y mejor documentación, ingrese al sitio web del 
    proyecto: http://hlbr.sourceforge.net (o http://hlbr.sf.net).



ACTUALIZACIÓN
-------------

Si usted está actualizando desde la versión 0.1-rc1 a 0.1-rc2, le sugerimos
que lleve a cabo una eliminación total de la versión 0.1-rc1 antes de 
instalar rc2. Esto es debido a que se produjeron muchos cambios entre las 
dos versiones. 0.1-rc2 es una versión más madura, y este procedimiento no
será necesario cuando la versión final 0.1 sea lanzada. 



ARCHIVOS DE REGLAS
------------------

Los archivos de reglas pueden contener reglas e incluír otros archivos, 
empleando la directiva <include>. Por ejemplo:

<include codered.rules>
<include nimda.rules>

Cualquier archivo de reglas puede ser cargado por HLBR mediante la opción
-r. Sin embargo consideramos /etc/hlbr/hlbr.rules como el archivo principal
de reglas.

Algunos <include> en /etc/hlbr/hlbr.rules pueden ser descomentados.
Esto significa que los archivos de reglas indicados por esos <include>
deberán ser analizados antes de ser activados y utilizados en ambientes
de producción. Esos archivos pueden contener reglas, que potencialmente,
pueden paralizar su red, dependiendo de qué esté usando en su red.


REGLAS HLBR
-----------

Ejemplo de una regla:

<rule>
ip dst(www)
tcp dst(80)
tcp nocase(cmd.exe)
message=Remote shell try cmd.exe
action=action1
</rule>

Todas las reglas comienzan con <rule> y terminan con </rule>. El directorio
contrib contiene las reglas originales del proyecto Hogwash, versión 0.5.
Sea cuidadoso con esas reglas, debido a que algunas de ellas son genéricas,
están desactualizadas y pueden contener opciones no soportadas por HLBR.
Sin embargo, dichas reglas pueden ser útiles para aprender acerca de cómo
crear reglas. En resumen , emplee solamente las reglas que se distribuyen
con HLBR en su ambiente de producción o desarrolle sus propias reglas! - no
es difícil.



EJEMPLOS DE OPCIONES DE REGLAS
------------------------------

interface name(eth0, eth1, eth5-eth6, ppp0)

    Coincide con una interfaz, varias interfaces o rangos de las mismas.
    
ethernet src(01:02:03:04:05:06)

    Coincide con una determinada dirección MAC origen. (no probada aún)
    
ethernet dst(01:02:03:04:05:06)

    Coincide con una determinada dirección MAC destino. (no probada aún)
    
ethernet type(IP, ARP, 0804)

    Coincide con uno o más protocolos, tal como están definidos en el campo
    "tipo" de la trama ethernet. El protocolo puede especificarse por su
    nombre o por su número. Ver definiciones del IANA [1]. (no probada aún)
    
ip src(10.10.10.2, WebServers, 192.168.0.0/16, 172.12.34.24-172.12.34.55)

    Coincide con una determinada dirección IP origen. Esta puede ser 
    especificada como una dirección IP única, una dirección de red, un rango
    o una lista de direcciones IP.
    
ip dst(10.10.10.2, WebServers, 192.168.0.0/16, 172.12.34.24-172.12.34.55)

    Coincide con una determinada dirección IP destino.

ip proto(TCP, UDP, ICMP, IGMP, PIM, OSPF, 13-15)

    Coincide con el tipo de protocolo transportado en el paquete IP. Los
    sistemas Unix tienen una lista de protocolos en /etc/protocols. 
    Ver IANA[4].
    
ip ttl(1-5)

    Verifica el valor del campo TTL. (no probada aún)
    
icmp code(6)

    Coincide con el código ICMP. Ver RFC 792 [2] y IANA [3]. (no probada aún)
    
icmp type(4)

    Coincide con el tipo ICMP. Ver RFC 792 [2] y IANA [3]. (no probada aún)
    
tcp src(80, 21-25)

    Coincide con el(los) puerto(s) TCP origen. Se pueden emplear varios
    puertos o rangos.
    Los sistemas Unix tienen una lista de puertos en /etc/services.
    
tcp dst(80, 21-25)

    Coincide con el(los) puerto(s) TCP destino.
    
udp src(53)

    Coincide con el(los) puerto(s) UDP origen.
    
udp dst(32000-32999, 53)

    Coincide con el(los) puerto(s) UDP destino.
    
tcp content(/etc/passwd)

    Coincide con el contenido dentro de un flujo TCP. Esta verificación
    es sensible a la diferencia entre mayúsculas y minúsculas.
    Los espacios se consideran como caracteres. La cadenas de bytes No-ASCII
    se pueden especificar en hexadecimal dentro de dos símbolos pipe ('|').
    
tcp nocase(default.ida? XXXXXXX)

    Similar a tcp content, pero ignora la diferencia entre mayúsculas y
    minúsculas.

udp content(bind|90 90 90|)

    Similar a tcp content, pero para segmentos UDP.
    
udp nocase(|90 90 90 90 90 90 90 90|)

    Similar a tcp nocase, pero para segmentos UDP.
    
tcp flags(Sfr)

    Verifica los flags de conexión TCP. La letras S, F, R, P, A, U, E, and C
    significan, respectivamente los flags SYN, FIN, RST, PSH, ACK, URG, EGE 
    y CWR. Si la letra es mayúscula el flag debe estar activado. Si la letra
    está en minúscula el flag debe estar desactivado. 
    Ver RFCs 793 [5] y 3168 [6]. (no probada aún)
    
tcp offset(10,Hello World)

    Verifica si la cadena especificada ("Hello world") se encuentra dentro del
    contenido (payload) TCP, comenzando desde el décimo byte. (no probada aún)



GARANTÍAS
---------

Todas las pruebas se realizaron sobre GNU/Linux Debian Sarge Stable R0a y R1.
Y funciono correctamente. Nosotros recomendamos DEBIAN!


REFERENCIAS
-----------

[1] http://www.iana.org/assignments/ethernet-numbers
[2] ftp://ftp.rfc-editor.org/in-notes/rfc792.txt
[3] http://www.iana.org/assignments/icmp-parameters
[4] http://www.iana.org/assignments/protocol-numbers
[5] ftp://ftp.rfc-editor.org/in-notes/rfc793.txt
[6] ftp://ftp.rfc-editor.org/in-notes/rfc3168.txt



AYÚDENOS!
---------

Necesitamos voluntarios para ayudar al equipo de desarrollo de HLBR. Tu 
puedes ayudarnos desarrollando código, probando HLBR, escribiendo reglas o
traduciendo documentos. Si estás interesado visita http://hlbr.sourceforge.net
para obtener más información.

Todo el trabajo realizado por voluntarios será probado, revisado y homologado
por los líderes del proyecto antes de ser lanzados para su uso en servidores
de producción.
