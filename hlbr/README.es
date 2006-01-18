HOGWASH LIGHT BR

INSTALACI�N
------------

Para instalar HLBR, siga los siguientes pasos:

1. Luego de extraer el tarball, ejecute el comando "# ./configure".

2. Ejecute el comando "# make". Ser�n necesario tener ya instalados los 
   compiladores para C (gcc) y C++.

3. Ejecute el comando "# make installes" para instalar HLBR con la versi�n
   en espa�ol del archivo de configuraci�n (los comentarios en el archivo
   estar�n en espa�ol). To install the file with comments in english, run 
   the command "# make installen". To install the file with comments in 
   brazilian portuguese, run the command "# make install".

4. Edite el archivo /etc/hlbr.config seg�n sea necesario.

5. Compile un nuevo kernel eliminando toda la pila de protocolos TCP/IP o
   configure las interfaces de red en el rango 127.0.0.0 (no use 127.0.0.1,
   ya que �sta ya est� en uso por la interfaz de loopback). Use direcciones
   como 127.0.0.2, 127.0.0.3 y similares. Recomendamos la segunda opci�n 
   en lugar de recompilar el kernel. Esto facilitar� la instalaci�n y le 
   permitir� utilizar otros programas para auditar el tr�fico como iptraf,
   TCPdump, y otros, ya que a�n existir� soporte IP (capa 3). Los datos 
   fluir�n por la capa 2 (enlace), pero seguir�n siendo visibles en la 
   capa 3 (red).

6. Para probar, ir al directorio /etc/hlbr y ejecutar:

    # hlbr -c hlbr.config -r empty.rules

	El daemon HLBR deber�a estar cargado.

7. Detener el servicio con Ctrl-C.

8. Cambiar los archivos de reglas (*.rules) dentro de /etc/hlbr/rules seg�n
   sea necesario. Esos archivos ser�n cargados por /etc/hlbr/hlbr.rules.

9. Para ejecutar HLBR, emplee:

    # hlbr -c hlbr.config -r hlbr.rules &
    
    o
    
    # /etc/init.d/hlbr start

10. Los logs (bit�coras) pueden encontrarse en /var/log/hlbr, a menos que 
    usted haya cambiado esta ubicaci�n en el archivo de configuraci�n
    (/etc/hlbr/hlbr.config) o use la opci�n -l (escriba "hlbr" para ver las
    opciones).

11. Para detenerlo, ejecute:

    # killall hlbr
    
    o
    
    # /etc/init.d/hlbr stop

12. Para desinstalar, emplee "# make uninstall". ADVERTENCIA: todos los 
    archivos de configuraci�n y logs ser�n eliminados.

13. Para "limpiar" le directorio del c�digo fuente (como si nunca hubiera 
    sido compilado), emplee "# make clean".

14. Para m�s informaci�n y mejor documentaci�n, ingrese al sitio web del 
    proyecto: http://hlbr.sourceforge.net (o http://hlbr.sf.net).



ACTUALIZACI�N
-------------

Si usted est� actualizando desde la versi�n 0.1-rc1 a 0.1-rc2, le sugerimos
que lleve a cabo una eliminaci�n total de la versi�n 0.1-rc1 antes de 
instalar rc2. Esto es debido a que se produjeron muchos cambios entre las 
dos versiones. 0.1-rc2 es una versi�n m�s madura, y este procedimiento no
ser� necesario cuando la versi�n final 0.1 sea lanzada. 



ARCHIVOS DE REGLAS
------------------

Los archivos de reglas pueden contener reglas e inclu�r otros archivos, 
empleando la directiva <include>. Por ejemplo:

<include codered.rules>
<include nimda.rules>

Cualquier archivo de reglas puede ser cargado por HLBR mediante la opci�n
-r. Sin embargo consideramos /etc/hlbr/hlbr.rules como el archivo principal
de reglas.

Algunos <include> en /etc/hlbr/hlbr.rules pueden ser descomentados.
Esto significa que los archivos de reglas indicados por esos <include>
deber�n ser analizados antes de ser activados y utilizados en ambientes
de producci�n. Esos archivos pueden contener reglas, que potencialmente,
pueden paralizar su red, dependiendo de qu� est� usando en su red.


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
contrib contiene las reglas originales del proyecto Hogwash, versi�n 0.5.
Sea cuidadoso con esas reglas, debido a que algunas de ellas son gen�ricas,
est�n desactualizadas y pueden contener opciones no soportadas por HLBR.
Sin embargo, dichas reglas pueden ser �tiles para aprender acerca de c�mo
crear reglas. En resumen , emplee solamente las reglas que se distribuyen
con HLBR en su ambiente de producci�n o desarrolle sus propias reglas! - no
es dif�cil.



EJEMPLOS DE OPCIONES DE REGLAS
------------------------------

interface name(eth0, eth1, eth5-eth6, ppp0)

    Coincide con una interfaz, varias interfaces o rangos de las mismas.
    
ethernet src(01:02:03:04:05:06)

    Coincide con una determinada direcci�n MAC origen. (no probada a�n)
    
ethernet dst(01:02:03:04:05:06)

    Coincide con una determinada direcci�n MAC destino. (no probada a�n)
    
ethernet type(IP, ARP, 0804)

    Coincide con uno o m�s protocolos, tal como est�n definidos en el campo
    "tipo" de la trama ethernet. El protocolo puede especificarse por su
    nombre o por su n�mero. Ver definiciones del IANA [1]. (no probada a�n)
    
ip src(10.10.10.2, WebServers, 192.168.0.0/16, 172.12.34.24-172.12.34.55)

    Coincide con una determinada direcci�n IP origen. Esta puede ser 
    especificada como una direcci�n IP �nica, una direcci�n de red, un rango
    o una lista de direcciones IP.
    
ip dst(10.10.10.2, WebServers, 192.168.0.0/16, 172.12.34.24-172.12.34.55)

    Coincide con una determinada direcci�n IP destino.

ip proto(TCP, UDP, ICMP, IGMP, PIM, OSPF, 13-15)

    Coincide con el tipo de protocolo transportado en el paquete IP. Los
    sistemas Unix tienen una lista de protocolos en /etc/protocols. 
    Ver IANA[4].
    
ip ttl(1-5)

    Verifica el valor del campo TTL. (no probada a�n)
    
icmp code(6)

    Coincide con el c�digo ICMP. Ver RFC 792 [2] y IANA [3]. (no probada a�n)
    
icmp type(4)

    Coincide con el tipo ICMP. Ver RFC 792 [2] y IANA [3]. (no probada a�n)
    
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

    Coincide con el contenido dentro de un flujo TCP. Esta verificaci�n
    es sensible a la diferencia entre may�sculas y min�sculas.
    Los espacios se consideran como caracteres. La cadenas de bytes No-ASCII
    se pueden especificar en hexadecimal dentro de dos s�mbolos pipe ('|').
    
tcp nocase(default.ida? XXXXXXX)

    Similar a tcp content, pero ignora la diferencia entre may�sculas y
    min�sculas.

udp content(bind|90 90 90|)

    Similar a tcp content, pero para segmentos UDP.
    
udp nocase(|90 90 90 90 90 90 90 90|)

    Similar a tcp nocase, pero para segmentos UDP.
    
tcp flags(Sfr)

    Verifica los flags de conexi�n TCP. La letras S, F, R, P, A, U, E, and C
    significan, respectivamente los flags SYN, FIN, RST, PSH, ACK, URG, EGE 
    y CWR. Si la letra es may�scula el flag debe estar activado. Si la letra
    est� en min�scula el flag debe estar desactivado. 
    Ver RFCs 793 [5] y 3168 [6]. (no probada a�n)
    
tcp offset(10,Hello World)

    Verifica si la cadena especificada ("Hello world") se encuentra dentro del
    contenido (payload) TCP, comenzando desde el d�cimo byte. (no probada a�n)



GARANT�AS
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



AY�DENOS!
---------

Necesitamos voluntarios para ayudar al equipo de desarrollo de HLBR. Tu 
puedes ayudarnos desarrollando c�digo, probando HLBR, escribiendo reglas o
traduciendo documentos. Si est�s interesado visita http://hlbr.sourceforge.net
para obtener m�s informaci�n.

Todo el trabajo realizado por voluntarios ser� probado, revisado y homologado
por los l�deres del proyecto antes de ser lanzados para su uso en servidores
de producci�n.
