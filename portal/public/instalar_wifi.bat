@echo off
:: Comprobar privilegios de administrador
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [ERROR] Este script debe ejecutarse como Administrador.
    echo Por favor, haz clic derecho sobre el archivo y selecciona "Ejecutar como administrador".
    pause
    exit /b
)

echo ======================================================
echo   Configurador Automático de Wi-Fi WPA-Enterprise
echo ======================================================
echo.

set PROFILE_NAME=wpa_enterprise_wifi.xml

if not exist "%PROFILE_NAME%" (
    echo [ERROR] No se encuentra el archivo de configuracion "%PROFILE_NAME%" en este directorio.
    echo Asegurate de que ambos archivos esten en la misma carpeta.
    pause
    exit /b
)

echo Importando perfil de red segura...
netsh wlan add profile filename="%PROFILE_NAME%" user=all >nul

if %errorLevel% eq 0 (
    echo.
    echo [OK] El perfil de red "EAPENT" ha sido configurado con exito.
    echo.
    echo [INFO] Ahora puedes hacer clic en el icono de Wi-Fi en la barra de tareas,
    echo        seleccionar la red "EAPENT", pulsar "Conectar" e ingresar tu usuario
    echo        y contrasenna institucional.
    echo.
) else (
    echo [ERROR] Ocurrio un problema al importar el perfil.
)

pause
