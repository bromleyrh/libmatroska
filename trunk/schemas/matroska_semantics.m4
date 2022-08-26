<!--
    matroska_semantics.m4
-->

<!--
include(`schemas/schema.m4')
-->

ppush(`EBMLSemantics')

<EBMLSemanticsSchema>

    pushe(`ElementHandler', `0xD7',
          `type="master" handler="matroska_tracknumber_handler"')
    nexte(`ElementHandler', `0xA3',
          `type="master" handler="matroska_simpleblock_handler"')
    nexte(`ElementHandler', `0x4254',
          `type="uinteger" handler="matroska_contentcompalgo_handler"')
    nexte(`ElementHandler', `0x4255',
          `type="binary" handler="matroska_contentcompsettings_handler"')
    ppop()

ppop()

</EBMLSemanticsSchema>

<!-- vi: set filetype=xml: -->
