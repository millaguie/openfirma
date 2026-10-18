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
 xfa-form.pdf         PDF con formulario: /AcroForm inline con /NeedAppearances
                      y /XFA. Entra en la regresion que comprueba que firmar
                      conserva esas claves (se injerta en el diccionario, no
                      se reconstruye).
 indirect-annots.pdf  PDF cuyo /Annots de pagina es un objeto indirecto, la
                      forma que escribe iText. Comprueba que sigue siendo
                      indirecto despues de firmar.
 twofields.pdf        Formulario con /AcroForm y DOS campos de firma vacios
                      (Firma1, Firma2), cada uno con su /Rect para que quien
                      firme pueda dibujar su apariencia donde el campo dice.
                      Generado por `tools/gen-testpdf.py --two-fields`.
                      Entra en la prueba de interoperabilidad con AutoFirma
                      (`crates/openfirma-pades/tests/autofirma_cosign.rs`):
                      AutoFirma firma Firma1 y despues Firma2 sobre su propia
                      salida, y en sentido contrario firma Firma2 sobre un
                      documento firmado por nosotros. La segunda pasada
                      construye la cadena de apariencia (`/AP /N`, y lo que esa
                      forma dibuja) que la puerta de revisiones tiene que
                      juzgar, y ademas iText re-sella el arbol de paginas con
                      `/ITXT (2.1.7)`.

 ns-root.xml        XML cuyo elemento raiz declara espacios de nombres (la
                    forma FacturaE) y un prefijo ds propio. Entra en el golden
                    XAdES: la canonicalizacion de SignedInfo y
                    SignedProperties debe llevar el contexto heredado de la
                    raiz (revision 03, C-1). Sin declaraciones XML:* ni texto
                    volatile: el diff sigue siendo estructural.
