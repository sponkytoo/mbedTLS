set TOOL="c:\Program Files (x86)\Microchip\xc32\v1.42\bin"

set FILE_DBG=".\dist\pic32mz_ef_sk\debug\wolfssl_tcp_client.X.debug.elf"
set FILE_PRD=".\dist\pic32mz_ef_sk\production\wolfssl_tcp_client.X.production.elf"

%TOOL%\xc32-readelf -a %FILE_DBG% > %FILE_DBG%.sym
c:\windows\system32\sort /+7 /rec 65535 %FILE_DBG%.sym > %FILE_DBG%.symbols.txt
del %FILE_DBG%.sym    
copy %FILE_DBG%.symbols.txt .
%TOOL%\xc32-objdump -S %FILE_DBG% > %FILE_DBG%.disassembly.txt
copy %FILE_DBG%.disassembly.txt .

%TOOL%\xc32-readelf -a %FILE_PRD% > %FILE_PRD%.sym
c:\windows\system32\sort /+7 /rec 65535 %FILE_PRD%.sym > %FILE_PRD%.symbols.txt
del %FILE_PRD%.sym    
copy %FILE_PRD%.symbols.txt .
%TOOL%\xc32-objdump -S %FILE_PRD% > %FILE_PRD%.disassembly.txt
copy %FILE_PRD%.disassembly.txt .