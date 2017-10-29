# mbedTLS
Shows how to use mbedTLS with Microchips Harmony Framework 2.04

- the used Hardware is the PIC32MZ2048EFH144 Ethernet Starterkit with the MCP2221 UART CDC-USB. 
  The real UART2 of the PIC is used for debugging and is connected to the MCP2221. 
- The Command "op" in the Terminal starts a TLS connection to https://www.googl.de. Read data, print them and closes. 
- Works with Harmony 2_04
- The Heap Managment is currently very wastefully adjusted. Should be alingned to the needs of the actual application.


