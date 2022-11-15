@ECHO OFF

::----------------------------------------------------------------------
:: Android Studio LightEdit mode script.
::----------------------------------------------------------------------

SET IDE_BIN_DIR=%~dp0
CALL "%IDE_BIN_DIR%\studio.bat" -e %*
