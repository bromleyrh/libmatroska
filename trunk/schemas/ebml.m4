<!--
    ebml.m4
-->

<!--
include(`schemas/schema.m4')
-->

<EBMLSchema xmlns="urn:ietf:rfc:8794" docType="ebml" version="1">

pushe(`EBML', `0x1A45DFA3',
      `type="master"' minmax(1, 1))

    pushe(`EBMLVersion', `0x4286',
          `type="uinteger" range="not 0" default="1"' minmax(1, 1))
    nexte(`EBMLReadVersion', `0x42F7',
          `type="uinteger" range="1" default="1"' minmax(1, 1))
    nexte(`EBMLMaxIDLength', `0x42F2',
          `type="uinteger" range=">=4" default="4"' minmax(1, 1))
    nexte(`EBMLMaxSizeLength', `0x42F3',
          `type="uinteger" range="not 0" default="8"' minmax(1, 1))

    nexte(`DocType', `0x4282',
          `type="string" length=">0"' minmax(1, 1))
    nexte(`DocTypeVersion', `0x4287',
          `type="uinteger" range="not 0" default="1"' minmax(1, 1))
    nexte(`DocTypeReadVersion', `0x4285',
          `type="uinteger" range="not 0" default="1"' minmax(1, 1))

    nexte(`DocTypeExtension', `0x4281',
          `type="master" minOccurs="0"')

        pushe(`DocTypeExtensionName', `0x4283',
              `type="string" length=">0"' minmax(1, 1))
        nexte(`DocTypeExtensionVersion', `0x4284',
              `type="uinteger" range="not 0"' minmax(1, 1))

        ppop()

    ppop()

ppop()

pushe(`CRC-32', `0xBF',
      `type="binary" length="4" maxOccurs="1"')

nexte(`Void', `0xEC',
      `type="binary"')

ppop()

</EBMLSchema>

<!-- vi: set filetype=xml: -->
