IPS-MikroTik-Suricata es una implementación de un módulo que se conecta a la base de datos MySQL del Suricata (utilizando Unified2 y Barnyard2) y busca por alertas predefinidas, en caso de encontrarla toma acción IPS conectándose al MikroTik RouterOS via API para bloquear el IP atacante.

Inspirado en un post de Tom Fisk del foro de MikroTik: http://forum.mikrotik.com/viewtopic.php?t=111727

Mirar la wiki para ver documentación: https://github.com/elmaxid/ips-mikrotik-suricata/wiki/Instalaci%C3%B3n-y-Uso

Lista de Cambios:

3 Marzo 17: v1.3

* Se hizo el schema de la DB con trigger, ahora no es necesario el Demonio mikrotik-ips-daemon_db.php
* Se actualizo la instalación

Requerimientos:

* Suricata funcionando
* Baynyard2 para guardar las alertas en MySql
* IP y datos de acceso de un MikroTik RouterOS
* GIT

** Funcionalidades

* Detecta alertas de Suricata y se conecta al RouterOS para bloquear el ataque
* Notificación de acción:
		* Correo electrónico
		* Telegram (API Bot)


Instalación:

Una vez que se tiene el Suricata instalado y funcionando en nuestra red, podemos proceder a la instalación de IPS-MikroTik-Suricata:

Disponemos de 5 archivos:

config.php:

Archivo de configuración con los datos de acceso a la DB y accesos a MikroTik

mikrotik-ips-daemon_db.php: 

Demonio que se conecta a la DB MySQL y detecta por patrones de Alertas y guarda en DB los datos para bloquear esa alerta.

mikrotik-ips-cron.php:

Demonio que toma las alertas de bloqueos y se conecta al MikroTik via API para agregar a una lista (firewall address-list) la dirección IP para luego bloquearla.

mikrotik-ips-clean.php: 

Demonio de limpieza y mantenimiento de la DB.

mikrotik-ips-install.php

Archivo de instalación y configuración. Crea las tablas con la estructura correspondiente. Chequea conexión API con MikroTik.


--
Para instalar hay que descargar el archivo y copiarlo al directorio /opt/ips-mikrotik-suricata

cd /opt

git clone https://github.com/elmaxid/ips-mikrotik-suricata.git

cd ips-mikrotik-suricata.git

-- para instalar y configurar

* Configurar archivo config.php  con los datos de la MySQL DB y MikroTik RouterOS API Access

Luego instalar schema DB Mysql

mysql -u username -p snorby < schema.sql

* Para chequear la configuración o Conexión con API ejecutar:

php -f mikrotik-ips-install.php

* Para ejecutar, setear  los permisos y ejecutar

chmod 777 /opt/ps-mikrotik-suricata.git/ips_start.sh 

* Modificar ip_start.sh con los  datos correctos (path)  y ejecutarlo para iniciar el trabajo

/opt/ips-mikrotik-suricata/./ips_start.sh 


----

Funcionamiento:

Para que el Suricata reciba el tráfico del MikroTik RouterOS hay que redirecionar el mismo, esto se puede realizar con Packet Sniffer o con Mangle Send To TZSP Action.
