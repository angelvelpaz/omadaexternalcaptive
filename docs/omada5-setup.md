# Configuración del Portal Cautivo en TP-Link Omada 5 o superior

## Requisitos previos

- Omada Software Controller **5.0 o superior** instalado y en ejecución
- Acceso de administrador al controlador
- El servidor del portal cautivo debe ser accesible por HTTPS desde los clientes Wi-Fi
- Certificado SSL válido o autofirmado aceptado en el controlador

---

## 1. Crear credenciales de Open API

El portal se comunica con Omada mediante la **Open API** con autenticación OAuth2 `client_credentials`. Debes crear un cliente de API con los permisos necesarios.

### 1.1 Acceder a la configuración de Open API

1. Inicia sesión en el controlador Omada.
2. En el menú lateral izquierdo, ve a **Settings** → **Open API**.
3. Haz clic en la pestaña **App Management**.

> En versiones anteriores a 5.9 esta sección puede llamarse **API Client** dentro de **Settings** → **Controller Settings**.

### 1.2 Crear el cliente de API

1. Haz clic en **+ Create**.
2. Completa los campos:

   | Campo | Valor |
   |-------|-------|
   | **App Name** | `Portal Cautivo` (o cualquier nombre descriptivo) |
   | **App Type** | `Server App` |
   | **Expire Time** | `Never` (o el período que prefieras) |

3. Haz clic en **Confirm**.
4. El sistema genera:
   - **Client ID** — identificador público del cliente
   - **Client Secret** — secreto; **cópialo ahora**, no se volverá a mostrar

5. Guarda ambos valores; los necesitarás en el paso 4.

### 1.3 Asignar permisos

En la entrada recién creada, haz clic en **Edit Permissions** y habilita:

- **Hotspot Manager** → **Write** (necesario para autorizar clientes)
- **Site** → **Read** (necesario para listar sitios y obtener el `omadacId`)

---

## 2. Obtener el identificador del sitio (omadacId)

El `omadacId` identifica de forma única tu instancia del controlador. El portal lo obtiene automáticamente durante la autenticación OAuth2; **no necesitas configurarlo manualmente** salvo que uses múltiples sitios.

Si necesitas el valor por referencia:

1. Ve a **Settings** → **Open API** → **API Documentation** (o abre `https://<controlador>:<puerto>/openapi/v1/token` en el navegador).
2. También aparece en la URL del panel cuando estás dentro de un sitio:
   ```
   https://<controlador>/#/site/<omadacId>/...
   ```

---

## 3. Configurar el portal externo en el SSID

### 3.1 Crear o editar el SSID

1. Ve a **Wireless** → **SSIDs** → selecciona o crea el SSID que usará el portal cautivo.
2. En la pestaña **Advanced**, busca la sección **Portal**.

> Dependiendo de la versión puede estar en **Hotspot** → **Portals** y luego asociarse al SSID.

### 3.2 Configurar el tipo de portal

1. En **Portal** habilita el toggle y selecciona **+ Create New Portal** (o edita uno existente).
2. Configura los campos:

   | Campo | Valor |
   |-------|-------|
   | **Portal Type** | `External Web Portal` |
   | **Authentication Type** | `No Authentication` *(la autenticación la gestiona el portal cautivo, no Omada)* |
   | **Portal URL** | `https://<ip-o-dominio-del-portal>/` |
   | **HTTPS Redirect** | Habilitado |

3. En **Portal Customization**, no se requiere configuración adicional para un portal externo.

### 3.3 Verificar los parámetros que Omada envía al portal

Al redirigir al cliente, Omada agrega los siguientes parámetros a la URL del portal:

| Parámetro | Descripción |
|-----------|-------------|
| `clientMac` | MAC del dispositivo cliente (formato `aa-bb-cc-dd-ee-ff`) |
| `apMac` | MAC del punto de acceso |
| `ssidName` | Nombre del SSID |
| `radioId` | ID del radio: `0` = 2.4 GHz, `1` = 5 GHz |
| `vid` | VLAN ID del cliente |
| `redirectUrl` | URL original a la que el cliente intentaba acceder |

Ejemplo de URL de redirección:
```
https://portal.empresa.com/?clientMac=aa-bb-cc-dd-ee-ff&apMac=11-22-33-44-55-66&ssidName=WiFi-Empresa&radioId=0&vid=1&redirectUrl=http%3A%2F%2Fexample.com
```

### 3.4 Whitelist del servidor del portal

Para que el cliente pueda acceder al portal **antes** de autenticarse, agrega la IP o dominio del servidor del portal a la lista de acceso libre:

1. En la configuración del portal, busca **Pre-Authentication Access** o **Free Access**.
2. Agrega la IP/dominio de tu servidor de portal cautivo.

---

## 4. Configurar las credenciales en el panel de administración

1. Accede al panel de administración del portal: `https://<portal>/admin/`
2. Inicia sesión con tu token de administrador.
3. Ve a la pestaña **Controladores**.
4. En la tarjeta **TP-Link Omada**, haz clic en **Configurar** e ingresa:

   | Campo | Valor |
   |-------|-------|
   | **URL del controlador** | `https://<ip-omada>:<puerto>` (ej: `https://192.168.1.2:8043`) |
   | **Client ID** | El Client ID obtenido en el paso 1.2 |
   | **Client Secret** | El Client Secret obtenido en el paso 1.2 |
   | **Site ID** | Dejar en blanco (se obtiene automáticamente) o el ID de tu sitio si tienes varios |

5. Haz clic en **Guardar**.
6. Haz clic en **Probar** para verificar la conectividad. Un resultado exitoso muestra el número de sitios disponibles.

---

## 5. Verificar el flujo completo

### Flujo de autenticación

```
[Cliente Wi-Fi]
    │  Intenta acceder a internet
    ▼
[Omada AP]
    │  Redirige a portal URL con parámetros (clientMac, apMac, etc.)
    ▼
[Portal Cautivo]
    │  El cliente ingresa su cédula
    │  El portal autentica contra FreeRADIUS
    │  En caso de éxito, llama a la Open API de Omada:
    │    POST /openapi/v1/{omadacId}/hotspot/extPortal/auth
    ▼
[Omada Controller]
    │  Autoriza al cliente por el tiempo configurado (SESSION_DURATION_MINUTES)
    ▼
[Cliente Wi-Fi] — Acceso a internet concedido
```

### Prueba manual

Desde un dispositivo conectado al SSID configurado:

1. Intenta abrir cualquier sitio HTTP (ej: `http://example.com`).
2. Omada debe redirigir al portal cautivo.
3. Ingresa una cédula válida registrada en el sistema.
4. Si la autenticación es exitosa, el portal llama a la API de Omada y el dispositivo obtiene acceso.

---

## 6. Solución de problemas

### Error: `Error 0: Open API Authorized failed`

- Verifica que el **Client ID** y **Client Secret** sean correctos y no tengan espacios extra.
- Confirma que el cliente de API tiene el permiso **Hotspot Manager → Write**.
- Verifica que el token no haya expirado (revisa **Expire Time** en la consola de Omada).

### Error: `HTTP 404` al llamar a la API

- La URL del controlador tiene un slash final (`/`) — elimínalo.
- El puerto es incorrecto. El puerto por defecto del Open API es el mismo que el del controlador web (normalmente `8043` para HTTPS).

### El cliente no es redirigido al portal

- Verifica que el dominio/IP del portal esté en la **whitelist de pre-autenticación** del portal en Omada.
- Asegúrate de que el SSID tiene asociado el portal configurado.
- El cliente debe intentar acceder a una URL HTTP (no HTTPS) para que Omada pueda interceptar la solicitud.

### El portal devuelve error al autorizar

- Revisa los logs del portal: `docker compose logs portal -f`
- Comprueba que el `omadacId` devuelto en el token sea correcto.
- Verifica que la MAC del cliente (`clientMac`) llega bien formateada al portal.

---

## 7. Notas de compatibilidad

| Versión Omada | Compatibilidad | Observaciones |
|---------------|---------------|---------------|
| 5.0 – 5.8 | ✅ Compatible | `accessToken` en campo `result` |
| 5.9+ | ✅ Compatible | Sin cambios en la API |
| 4.x | ⚠️ Parcial | `accessToken` puede estar en campo `data`; probar con precaución |
| 3.x o inferior | ❌ No compatible | No tiene Open API |

La implementación detecta automáticamente si el token está en `result` o `data` para mantener compatibilidad con controladores pre-5.x.
