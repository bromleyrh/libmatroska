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
    ppop()

ppop()

</EBMLSemanticsSchema>

<!-- vi: set filetype=xml: -->
