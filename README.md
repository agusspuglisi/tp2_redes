# tp2_redes

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
