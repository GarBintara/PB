@ECHO OFF

::----------------------------------------------------------------------
:: Android Studio formatting script.
::----------------------------------------------------------------------

SET IDE_BIN_DIR=%~dp0
CALL "%IDE_BIN_DIR%\studio.bat" format %*
