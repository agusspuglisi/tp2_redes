# tp2_redes

## Requisitos

Este proyecto requiere [POX](https://github.com/noxrepo/pox) como controlador SDN para funcionar.

1. Cloná POX dentro de la carpeta raíz del proyecto:

   ```bash
   git clone https://github.com/noxrepo/pox.git

2. No incluir POX en tu repositorio Git. Esta en gitignore, se necesita de manera local.

## Cómo ejecutar la topología parametrizable

Para lanzar la topología en cadena implementada en `topo/topologia.py`, usá el siguiente comando desde la raíz del proyecto:

```bash
sudo mn --custom topo/topologia.py --topo chain,5 --mac --arp
```

### ¿Qué hace cada parte del comando?

- `--custom topo/topologia.py`: le indica a Mininet que use nuestro archivo Python personalizado para definir la topología.

- `--topo chain,5`: usa la topología llamada `chain` con 5 switches conectados en cadena. Podés cambiar el número (`5`) por cualquier cantidad de switches que quieras probar.

- `--mac`: asigna direcciones MAC automáticas a los hosts.

- `--arp`: habilita la resolución automática de direcciones IP con ARP.

## Cómo ejecutar el controlador firewall básico

0. Copiar el controlador al lugar esperado por POX

El archivo controller/firewall.py debe estar ubicado en pox/pox/ext/. Copialo con:

```bash
cp controller/firewall.py pox/pox/ext/firewall.py
```
Si ya se habia copiado antes, asegurase de que sea la versión más reciente.

1. Asegurate de estar dentro de la carpeta pox/:

```bash
cd pox
```
2. Ejecutá el controlador desde POX:

```bash
./pox.py log.level --DEBUG ext.firewall
```

3. En otra terminal, levantá Mininet con el controlador remoto:

```bash
sudo mn --custom topo/topologia.py --topo chain,3 --mac --arp --controller=remote
```

4. En la CLI de Mininet, probá conectividad:

```bash
pingall
```