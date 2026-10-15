 Corpus fijo de entradas para el golden diff.

 Estos ficheros se commitean a proposito: son sinteticos, no contienen nada
 sensible, y hacen que la comparacion contra AutoFirma sea reproducible en
 cualquier maquina. Las firmas generadas con ellos no se commitean, van a
 testdata/golden, que esta ignorado.

 simple.txt  texto plano con acentos y eñes, para contentHint "Texto plano"
 simple.pdf  PDF minimo de una pagina, generado por tools/gen-testpdf.py.
             Sin /Info, sin fechas y sin cadena de productor: cualquier valor
             volatile acabaria en el golden y convertiria un diff estructural
             en ruido. Regeneralo con esa script si cambia.
