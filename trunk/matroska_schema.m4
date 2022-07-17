<!--
    matroska_schema.m4
-->

<!--
include(`schema_util.m4')

define(`ppush', `push(`pathstr', $1)')
define(`ppop', `pop(`pathstr')')
define(`pnext', `next(`pathstr', $1)')

define(`_elems', `<element name="bname(pathstr)" path="pathstr" id="$1" $2')

define(`elem', `_elems($1, $2)/>')
define(`elems', `_elems($1, $2)>')
define(`eleme', `</element>')

define(`pushe', `ppush($1)elem($2, $3)')
define(`pushes', `ppush($1)elems($2, $3)')
define(`epushes', `eleme()ppush($1)elems($2, $3)')

define(`epop', `eleme()ppop()')

define(`nexte', `pnext($1)elem($2, $3)')
define(`enexte', `eleme()pnext($1)elem($2, $3)')
define(`enextes', `eleme()pnext($1)elems($2, $3)')

define(`minmax', `minOccurs="$1" maxOccurs="$2"')
define(`minmaxver', `minver="$1" maxver="$2"')

define(`_enuments', `<enum value="$1" label="$2"')

define(`enument', `_enuments($1, $2)/>')
define(`enuments', `_enuments($1, $2)>')
define(`eenuments', `enumente()enuments($1, $2)')
define(`enumente', `</enum>')

define(`def',
       `<documentation lang="en" purpose="definition">$1</documentation>')
define(`usage',
       `<documentation lang="en" purpose="`usage' notes">$1</documentation>')
-->

ppush(`EBML')

<EBMLSchema xmlns="urn:ietf:rfc:8794" docType="matroska" version="4">

    <!-- constraints on EBML Header Elements -->

    pushe(`EBMLMaxIDLength', `0x42F2',
          `type="uinteger" range="4" default="4"' minmax(1, 1))
    nexte(`EBMLMaxSizeLength', `0x42F3',
          `type="uinteger" range="1-8" default="8"' minmax(1, 1))
    ppop()

ppop()

<!-- Root Element-->

<!-- \Segment -->
pushes(`Segment', `0x18538067',
       `type="master" minOccurs="1" maxOccurs="1" unknownsizeallowed="1"')

    def(`
The Root Element that contains all other Top-Level Elements (Elements defined
only at Level 1). A Matroska file is composed of 1 Segment.
    ')

    <!-- \Segment\SeekHead -->
    epushes(`SeekHead', `0x114D9B74',
            `type="master" maxOccurs="2"')

        def(`
Contains the Segment Position of other Top-Level Elements.
        ')
        <extension type="webmproject.org" webm="1"/>

        <!-- \Segment\SeekHead\Seek -->
        epushes(`Seek', `0x4DBB',
                `type="master" minOccurs="1"')

            def(`
Contains a single seek entry to an EBML Element.
            ')
            <extension type="webmproject.org" webm="1"/>

            <!-- \Segment\SeekHead\Seek\SeekID -->
            epushes(`SeekID', `0x53AB',
                    `type="binary" length="&lt;= 4"' minmax(1, 1))

                def(`
The binary ID corresponding to the Element name.
                ')
                <extension type="webmproject.org" webm="1"/>

            <!-- \Segment\SeekHead\Seek\SeekPosition -->
            enextes(`SeekPosition', `0x53AC',
                    `type="uinteger"' minmax(1, 1))

                def(`
The Segment Position of the Element.
                ')
                <extension type="webmproject.org" webm="1"/>

            epop()

        ppop()

    ppop()

    <!-- \Segment\Info -->
    pushes(`Info', `0x1549A966',
           `type="master"' minmax(1, 1) `recurring="1"')

        def(`
Contains general information about the Segment.
        ')
        <extension type="webmproject.org" webm="1"/>

        <!-- \Segment\Info\SegmentUID -->
        epushes(`SegmentUID', `0x73A4',
                `type="binary" range="not 0" length="16" maxOccurs="1"')

            def(`
A randomly generated unique ID to identify the Segment amongst many others (128
bits).
            ')
            usage(`
If the Segment is a part of a Linked Segment, then this Element is **REQUIRED**.
            ')

        <!-- \Segment\Info\SegmentFilename -->
        enextes(`SegmentFilename', `0x7384',
                `type="utf-8" maxOccurs="1"')

            def(`
A filename corresponding to this Segment.
            ')

        <!-- \Segment\Info\PrevUID -->
        enextes(`PrevUID', `0x3CB923'
                `type="binary" length="16" maxOccurs="1"')

            def(`
A unique ID to identify the previous Segment of a Linked Segment (128 bits).
            ')
            usage(`
If the Segment is a part of a Linked Segment that uses Hard Linking, then either
the PrevUID or the NextUID Element is **REQUIRED**. If a Segment contains a
PrevUID but not a NextUID, then it **MAY** be considered as the last Segment of
the Linked Segment. The PrevUID **MUST NOT** be equal to the SegmentUID.
            ')

        <!-- \Segment\Info\PrevFilename -->
        enextes(`PrevFilename', `0x3C83AB',
                `type="utf-8" maxOccurs="1"')

            def(`
A filename corresponding to the file of the previous Linked Segment.
            ')
            usage(`
Provision of the previous filename is for display convenience, but PrevUID
**SHOULD** be considered authoritative for identifying the previous Segment in a
Linked Segment.
            ')

        <!-- \Segment\Info\NextUID -->
        enextes(`NextUID', `0x3EB923',
                `type="binary" length="16" maxOccurs="1"')

            def(`
A unique ID to identify the next Segment of a Linked Segment (128 bits).
            ')
            usage(`
If the Segment is a part of a Linked Segment that uses Hard Linking, then either
the PrevUID or the NextUID Element is **REQUIRED**. If a Segment contains a
NextUID but not a PrevUID, then it **MAY** be considered as the first Segment of
the Linked Segment. The NextUID **MUST NOT** be equal to the SegmentUID.
            ')

        <!-- \Segment\Info\NextFilename -->
        enextes(`NextFilename', `0x3E83BB',
                `type="utf-8" maxOccurs="1"')

            def(`
A filename corresponding to the file of the next Linked Segment.
            ')
            usage(`
Provision of the next filename is for display convenience, but NextUID
**SHOULD** be considered authoritative for identifying the Next Segment.
            ')

        <!-- \Segment\Info\SegmentFamily -->
        enextes(`SegmentFamily', `0x4444',
                `type="binary" length="16"')

            def(`
A randomly generated unique ID that all Segments of a Linked Segment **MUST**
share (128 bits).
            ')
            usage(`
If the Segment Info contains a "ChapterTranslate" element, this Element is
**REQUIRED**.
            ')

        <!-- \Segment\Info\ChapterTranslate -->
        enextes(`ChapterTranslate', `0x6924',
                `type="master"')

            def(`
The mapping between this "Segment" and a segment value in the given Chapter
Codec.
            ')
            <documentation lang="en" purpose="rationale">
Chapter Codec may need to address different segments, but they may not know of
the way to identify such segment when stored in Matroska. This element and its
child elements add a way to map the internal segments known to the Chapter Codec
to the Segment IDs in Matroska. This allows remuxing a file with Chapter Codec
without changing the content of the codec data, just the Segment mapping.
            </documentation>

            <!-- \Segment\Info\ChapterTranslate\ChapterTranslateID -->
            epushes(`ChapterTranslateID', `0x69A5',
                    `type="binary"' minmax(1, 1))

                def(`
The binary value used to represent this Segment in the chapter codec data. The
format depends on the ChapProcessCodecID used; see
(#chapprocesscodecid-element).
                ')

            <!-- \Segment\Info\ChapterTranslate\ChapterTranslateCodec -->
            enextes(`ChapterTranslateCodec', `0x69BF',
                    `type="uinteger"' minmax(1, 1))

                def(`
This "ChapterTranslate" applies to this chapter codec of the given chapter
edition(s); see (#chapprocesscodecid-element).
                ')
                <restriction>
                    <enum value="0" label="Matroska Script">
                        def(`
Chapter commands using the Matroska Script codec.
                        ')
                    </enum>
                    <enum value="1" label="DVD-menu">
                        def(`
Chapter commands using the DVD-like codec.
                        ')
                    </enum>
                </restriction>

            <!-- \Segment\Info\ChapterTranslate\ChapterTranslateEditionUID -->
            enextes(`ChapterTranslateEditionUID', `0x69FC',
                    `type="uinteger"')

                def(`
Specify a chapter edition UID on which this "ChapterTranslate" applies.
                ')
                usage(`
When no "ChapterTranslateEditionUID" is specified in the "ChapterTranslate", the
"ChapterTranslate" applied to all chapter editions found in the Segment using
the given "ChapterTranslateCodec".
                ')

            epop()

        ppop()

        <!-- \Segment\Info\TimestampScale -->
        epushes(`TimestampScale', `0x2AD7B1',
               `type="uinteger" range="not 0" default="1000000"' minmax(1, 1))

            def(`
Base unit for Segment Ticks and Track Ticks, in nanoseconds. A TimestampScale
value of 1.000.000 means scaled timestamps in the Segment are expressed in
milliseconds; see (#timestamps) on how to interpret timestamps.
            ')
            <extension type="libmatroska" cppname="TimecodeScale"/>
            <extension type="webmproject.org" webm="1"/>

        <!-- \Segment\Info\Duration -->
        enextes(`Duration', `0x4489',
                `type="float" range="&gt; 0x0p+0" maxOccurs="1"')

            def(`
Duration of the Segment, expressed in Segment Ticks which is based on
TimestampScale; see (#timestamp-ticks).
            ')
            <extension type="webmproject.org" webm="1"/>

        <!-- \Segment\Info\DateUTC -->
        enextes(`DateUTC', `0x4461',
                `type="date" maxOccurs="1"')

            def(`
The date and time that the Segment was created by the muxing application or
library.
            ')
            <extension type="webmproject.org" webm="1"/>

        <!-- \Segment\Info\Title -->
        enextes(`Title', `0x7BA9',
                `type="utf-8" maxOccurs="1"')

            def(`
General name of the Segment.
            ')
            <extension type="webmproject.org" webm="1"/>

        <!-- \Segment\Info\MuxingApp -->
        enextes(`MuxingApp', `0x4D80',
                `type="utf-8" minmax(1, 1)')

            def(`
Muxing application or library (example: "libmatroska-0.4.3").
            ')
            usage(`
Include the full name of the application or library followed by the version
number.
            ')
            <extension type="webmproject.org" webm="1"/>

        <!-- \Segment\Info\WritingApp -->
        enextes(`WritingApp', `0x5741',
                `type="utf-8" minmax(1, 1)')

            def(`
Writing application (example: "mkvmerge-0.3.3").
            ')
            usage(`
Include the full name of the application followed by the version number.
            ')
            <extension type="webmproject.org" webm="1"/>

        epop()

    ppop()

    <!-- \Segment\Cluster -->
    pushes(`Cluster', `0x1F43B675',
           `type="master" unknownsizeallowed="1"')

        def(`
The Top-Level Element containing the (monolithic) Block structure.
        ')
        <extension type="webmproject.org" webm="1"/>

        <!-- \Segment\Cluster\Timestamp -->
        epushes(`Timestamp', `0xE7'
                `type="uinteger"' minmax(1, 1))

            def(`
Absolute timestamp of the cluster, expressed in Segment Ticks which is based on
TimestampScale; see (#timestamp-ticks).
            ')
            usage(`
This element **SHOULD** be the first child element of the Cluster it belongs to,
or the second if that Cluster contains a CRC-32 element ((#crc-32)).
            ')
            <extension type="libmatroska" cppname="ClusterTimecode"/>
            <extension type="webmproject.org" webm="1"/>

        <!-- \Segment\Cluster\SilentTracks -->
        enextes(`SilentTracks', `0x5854',
                `type="master"' minmaxver(0, 0) `maxOccurs="1"')

            def(`
The list of tracks that are not used in that part of the stream. It is useful
when using overlay tracks on seeking or to decide what track to use.
            ')
            <extension type="libmatroska" cppname="ClusterSilentTracks"/>

            <!-- \Segment\Cluster\SilentTracks\SilentTrackNumber -->
            epushes(`SilentTrackNumber', `0x58D7',
                    `type="uinteger"' minmaxver(0, 0))

                def(`
One of the track number that are not used from now on in the stream. It could
change later if not specified as silent in a further Cluster.
                ')
                <extension type="libmatroska"
                 cppname="ClusterSilentTrackNumber"/>

            epop()

        ppop()

        <!-- \Segment\Cluster\Position -->
        pushes(`Position', `0xA7',
               `type="uinteger" maxOccurs="1"')

            def(`
The Segment Position of the Cluster in the Segment (0 in live streams). It might
help to resynchronise offset on damaged streams.
            ')
            <extension type="libmatroska" cppname="ClusterPosition"/>

        <!-- \Segment\Cluster\PrevSize -->
        enextes(`PrevSize', `0xAB',
                `type="uinteger" maxOccurs="1"')

            def(`
Size of the previous Cluster, in octets. Can be useful for backward playing.
            ')
            <extension type="libmatroska" cppname="ClusterPrevSize"/>
            <extension type="webmproject.org" webm="1"/>

        <!-- \Segment\Cluster\SimpleBlock -->
        enextes(`SimpleBlock', `0xA3',
                `type="binary" minver="2"')

            def(`
Similar to Block, see (#block-structure), but without all the extra information,
mostly used to reduce overhead when no extra feature is needed; see
(#simpleblock-structure) on SimpleBlock Structure.
            ')
            <extension type="webmproject.org" webm="1"/>
            <extension type="divx.com" divx="1"/>

        <!-- \Segment\Cluster\BlockGroup -->
        enextes(`BlockGroup', `0xA0',
                `type="master"')

            def(`
Basic container of information containing a single Block and information
specific to that Block.
            ')
            <extension type="webmproject.org" webm="1"/>

            <!-- \Segment\Cluster\BlockGroup\Block -->
            epushes(`Block', `0xA1',
                    `type="binary"' minmax(1, 1))

                def(`
Block containing the actual data to be rendered and a timestamp relative to the
Cluster Timestamp; see (#block-structure) on Block Structure.
                ')
                <extension type="webmproject.org" webm="1"/>

            <!-- \Segment\Cluster\BlockGroup\BlockVirtual -->
            enextes(`BlockVirtual', `0xA2',
                    `type="binary"' minmaxver(0, 0) `maxOccurs="1"')

                def(`
A Block with no data. It **MUST** be stored in the stream at the place the real
Block would be in display order.
                ')

            <!-- \Segment\Cluster\BlockGroup\BlockAdditions -->
            enextes(`BlockAdditions', `0x75A1',
                    `type="master" maxOccurs="1"')

                def(`
Contain additional blocks to complete the main one. An EBML parser that has no
knowledge of the Block structure could still see and use/skip these data.
                ')
                <extension type="webmproject.org" webm="1"/>

                <!-- \Segment\Cluster\BlockGroup\BlockAdditions\BlockMore -->
                epushes(`BlockMore', `0xA6',
                        `type="master" minOccurs="1"')

                    def(`
Contain the BlockAdditional and some parameters.
                    ')
                    <extension type="webmproject.org" webm="1"/>

                    <!-- \Segment\Cluster\BlockGroup\BlockAdditions\BlockMore
                         \BlockAddID -->
                    epushes(`BlockAddID', `0xEE',
                            `type="uinteger" range="not 0" default="1"'
                            minmax(1, 1)')

                        def(`
An ID to identify the BlockAdditional level. If BlockAddIDType of the
corresponding block is 0, this value is also the value of BlockAddIDType for the
meaning of the content of BlockAdditional.
                        ')
                        <extension type="webmproject.org" webm="1"/>

                    <!-- \Segment\Cluster\BlockGroup\BlockAdditions\BlockMore
                         \BlockAdditional -->
                    enextes(`BlockAdditional', `0xA5',
                            `type="binary"' minmax(1, 1))

                        def(`
Interpreted by the codec as it wishes (using the BlockAddID).
                        ')
                        <extension type="webmproject.org" webm="1"/>

                    epop()

                ppop()

            ppop()

            <!-- \Segment\Cluster\BlockGroup\BlockDuration -->
            pushes(`BlockDuration', `0x9B',
                   `type="uinteger" maxOccurs="1"')

                def(`
The duration of the Block, expressed in Track Ticks; see (#timestamp-ticks). The
BlockDuration Element can be useful at the end of a Track to define the duration
of the last frame (as there is no subsequent Block available), or when there is
a break in a track like for subtitle tracks.
                ')
                <implementation_note note_attribute="minOccurs">
BlockDuration **MUST** be set (minOccurs=1) if the associated TrackEntry stores
a DefaultDuration value.
                </implementation_note>
                <implementation_note note_attribute="default">
When not written and with no DefaultDuration, the value is assumed to be the
difference between the timestamp of this Block and the timestamp of the next
Block in "display" order (not coding order).
                </implementation_note>
                <extension type="webmproject.org" webm="1"/>

            <!-- \Segment\Cluster\BlockGroup\ReferencePriority -->
            enextes(`ReferencePriority', `0xFA',
                    `type="uinteger" default="0"' minmax(1, 1))

                def(`
This frame is referenced and has the specified cache priority. In cache only a
frame of the same or higher priority can replace this frame. A value of 0 means
the frame is not referenced.
                ')

            <!-- \Segment\Cluster\BlockGroup\ReferenceBlock -->
            enextes(`ReferenceBlock', `0xFB',
                    `type="integer"')

                def(`
A timestamp value, relative to the timestamp of the Block in this BlockGroup,
expressed in Track Ticks; see (#timestamp-ticks). This is used to reference
other frames necessary to decode this frame. The relative value **SHOULD**
correspond to a valid "Block" this "Block" depends on. Historically Matroska
Writer didnt write the actual "Block(s)" this "Block" depends on, but *some*
"Block" in the past.

The value "0" **MAY** also be used to signify this "Block" cannot be decoded on
its own, but without knownledge of which "Block" is necessary. In this case,
other "ReferenceBlock" **MUST NOT** be found in the same "BlockGroup".

If the "BlockGroup" doesn't have any "ReferenceBlock" element, then the "Block"
it contains can be decoded without using any other "Block" data.
                ')
                <extension type="webmproject.org" webm="1"/>

            <!-- \Segment\Cluster\BlockGroup\ReferenceVirtual -->
            enextes(`ReferenceVirtual', `0xFD',
                    `type="integer"' minmaxver(0, 0) `maxOccurs="1"')

                def(`
The Segment Position of the data that would otherwise be in position of the
virtual block.
                ')

            <!-- \Segment\Cluster\BlockGroup\CodecState -->
            enextes(`CodecState', `0xA4',
                    `type="binary" minver="2" maxOccurs="1"')

                def(`
The new codec state to use. Data interpretation is private to the codec. This
information **SHOULD** always be referenced by a seek entry.
                ')

            <!-- \Segment\Cluster\BlockGroup\DiscardPadding -->
            enextes(`DiscardPadding', `0x75A2',
                    `type="integer" minver="4" maxOccurs="1"')

                def(`
Duration of the silent data added to the Block, expressed in Matroska Ticks --
ie in nanoseconds; see (#timestamp-ticks) (padding at the end of the Block for
positive value, at the beginning of the Block for negative value). The duration
of DiscardPadding is not calculated in the duration of the TrackEntry and
**SHOULD** be discarded during playback.
                ')
                <extension type="webmproject.org" webm="1"/>

            <!-- \Segment\Cluster\BlockGroup\Slices -->
            enextes(`Slices', `0x8E',
                    `type="master"' minmaxver(0, 0) `maxOccurs="1"')

                def(`
Contains slices description.
                ')

                <!-- \Segment\Cluster\BlockGroup\Slices\TimeSlice -->
                epushes(`TimeSlice', `0xE8',
                        `type="master"' minmaxver(0, 0))

                    def(`
Contains extra time information about the data contained in the Block. Being
able to interpret this Element is not **REQUIRED** for playback.
                    ')

                    <!-- \Segment\Cluster\BlockGroup\Slices\TimeSlice
                         \LaceNumber -->
                    epushes(`LaceNumber', `0xCC',
                            `type="uinteger"' minmaxver(0, 0) `maxOccurs="1"')

                        def(`
The reverse number of the frame in the lace (0 is the last frame, 1 is the next
to last, etc). Being able to interpret this Element is not **REQUIRED** for
playback.
                        ')
                        <extension type="libmatroska"
                         cppname="SliceLaceNumber"/>

                    <!-- \Segment\Cluster\BlockGroup\Slices\TimeSlice
                         \FrameNumber -->
                    enextes(`FrameNumber', `0xCD',
                            `type="uinteger"' minmaxver(0, 0)
                            `default="0" maxOccurs="1"')

                        def(`
The number of the frame to generate from this lace with this delay (allow you to
generate many frames from the same Block/Frame).
                        ')
                        <extension type="libmatroska"
                         cppname="SliceFrameNumber"/>

                    <!-- \Segment\Cluster\BlockGroup\Slices\TimeSlice
                         \BlockAdditionID -->
                    enextes(`BlockAdditionID', `0xCB',
                            `type="uinteger"' minmaxver(0, 0)
                            `default="0" maxOccurs="1"')

                        def(`
The ID of the BlockAdditional Element (0 is the main Block).
                        ')
                        <extension type="libmatroska"
                         cppname="SliceBlockAddID"/>

                    <!-- \Segment\Cluster\BlockGroup\Slices\TimeSlice\Delay -->
                    enextes(`Delay', `0xCE',
                            `type="uinteger"' minmaxver(0, 0)
                            `default="0" maxOccurs="1"')

                        def(`
The delay to apply to the Element, expressed in Track Ticks; see
(#timestamp-ticks).
                        ')
                        <extension type="libmatroska" cppname="SliceDelay"/>

                    <!-- \Segment\Cluster\BlockGroup\Slices\TimeSlice
                         \SliceDuration -->
                    enextes(`SliceDuration', `0xCF',
                            `type="uinteger"' minmaxver(0, 0)
                            `default="0" maxOccurs="1"')

                        def(`
The duration to apply to the Element, expressed in Track Ticks; see
(#timestamp-ticks).
                        ')

                    epop()

                ppop()

            ppop()

            <!-- \Segment\Cluster\BlockGroup\ReferenceFrame -->
            pushes(`ReferenceFrame', `0xC8',
                   `type="master"' minmaxver(0, 0) `maxOccurs="1"')

                def(`
Contains information about the last reference frame. See [@?DivXTrickTrack].
                ')
                <extension type="divx.com" divx="1"/>

                <!-- \Segment\Cluster\BlockGroup\ReferenceFrame
                     \ReferenceOffset -->
                epushes(`ReferenceOffset', `0xC9',
                        `type="uinteger"' minmaxver(0, 0) minmax(1, 1))

                    def(`
The relative offset, in bytes, from the previous BlockGroup element for this
Smooth FF/RW video track to the containing BlockGroup element. See
[@?DivXTrickTrack].
                    ')
                    <extension type="divx.com" divx="1"/>

                <!-- \Segment\Cluster\BlockGroup\ReferenceFrame
                     \ReferenceTimestamp -->
                enextes(`ReferenceTimestamp', `0xCA',
                        `type="uinteger"' minmaxver(0, 0) minmax(1, 1))

                    def(`
The timestamp of the BlockGroup pointed to by ReferenceOffset, expressed in
Track Ticks; see (#timestamp-ticks). See [@?DivXTrickTrack].
                    ')
                    <extension type="libmatroska" cppname="ReferenceTimeCode"/>
                    <extension type="divx.com" divx="1"/>

                epop()

            ppop()

        ppop()

        <!-- \Segment\Cluster\EncryptedBlock -->
        pushes(`EncryptedBlock', `0xAF',
               `type="binary"' minmaxver(0, 0))

            def(`
Similar to SimpleBlock, see (#simpleblock-structure), but the data inside the
Block are Transformed (encrypt and/or signed).
            ')

        epop()

    ppop()

    <!-- \Segment\Tracks -->
    pushes(`Tracks', `0x1654AE6B'
           `type="master" maxOccurs="1" recurring="1"')

        def(`
A Top-Level Element of information with many tracks described.
        ')
        <extension type="webmproject.org" webm="1"/>

        <!-- \Segment\Tracks\TrackEntry -->
        epushes(`TrackEntry', `0xAE',
                `type="master" minOccurs="1"')

            def(`
Describes a track with all Elements.
            ')
            <extension type="webmproject.org" webm="1"/>

            <!-- \Segment\Tracks\TrackEntry\TrackNumber -->
            epushes(`TrackNumber', `0xD7',
                    `type="uinteger" range="not 0"' minmax(1, 1))

                def(`
The track number as used in the Block Header (using more than 127 tracks is not
encouraged, though the design allows an unlimited number).
                ')
                <extension type="webmproject.org" webm="1"/>

            <!-- \Segment\Tracks\TrackEntry\TrackUID -->
            enextes(`TrackUID', `0x73C5',
                    `type="uinteger" range="not 0"' minmax(1, 1))

                def(`
A unique ID to identify the Track.
                ')
                <extension type="stream copy" keep="1"/>
                <extension type="webmproject.org" webm="1"/>

            <!-- \Segment\Tracks\TrackEntry\TrackType -->
            enextes(`TrackType', `0x83',
                    `type="uinteger"' minmax(1, 1))

                def(`
The "TrackType" defines the type of each frame found in the Track. The value
**SHOULD** be stored on 1 octet.
                ')
                <restriction>
                    enuments(1, `video')
                        def(`
An image.
                        ')
                    eenuments(2, `audio')
                        def(`
Audio samples.
                        ')
                    eenuments(3, `complex')
                        def(`
A mix of different other TrackType. The codec needs to define how the "Matroska
Player" should interpret such data.
                        ')
                    eenuments(16, `logo')
                        def(`
An image to be rendered over the video track(s).
                        ')
                    eenuments(17, `subtitle')
                        def(`
Subtitle or closed caption data to be rendered over the video track(s).
                        ')
                    eenuments(18, `buttons')
                        def(`
Interactive button(s) to be rendered over the video track(s).
                        ')
                    eenuments(32, `control')
                        def(`
Metadata used to control the player of the "Matroska Player".
                        ')
                    eenuments(33, `metadata')
                        def(`
Timed metadata that can be passed on to the "Matroska Player".
                        ')
                    enumente()
                </restriction>
                <extension type="stream copy" keep="1"/>
                <extension type="webmproject.org" webm="1"/>

            <!-- \Segment\Tracks\TrackEntry\FlagEnabled -->
            enextes(`FlagEnabled', `0xB9',
                    `type="uinteger" range="0-1" minver="2" default="1"'
                    minmax(1, 1))

                def(`
Set to 1 if the track is usable. It is possible to turn a not usable track into
a usable track using chapter codecs or control tracks.
                ')
                <extension type="webmproject.org" webm="1"/>
                <extension type="libmatroska" cppname="TrackFlagEnabled"/>

            <!-- \Segment\Tracks\TrackEntry\FlagDefault -->
            enextes(`FlagDefault', `0x88',
                    `type="uinteger" range="0-1" default="1"' minmax(1, 1))

                def(`
Set if that track (audio, video or subs) **SHOULD** be eligible for automatic
selection by the player; see (#default-track-selection) for more details.
                ')
                <extension type="libmatroska" cppname="TrackFlagDefault"/>
                <extension type="webmproject.org" webm="1"/>

            <!-- \Segment\Tracks\TrackEntry\FlagForced -->
            enextes(`FlagForced', `0x55AA',
                    `type="uinteger" range="0-1" default="0"' minmax(1, 1))

                def(`
Applies only to subtitles. Set if that track **SHOULD** be eligible for
automatic selection by the player if it matches the users language preference,
even if the users preferences would normally not enable subtitles with the
selected audio track; this can be used for tracks containing only translations
of foreign-language audio or onscreen text. See (#default-track-selection) for
more details.
                ')
                <extension type="libmatroska" cppname="TrackFlagForced"/>
                <extension type="webmproject.org" webm="1"/>

            <!-- \Segment\Tracks\TrackEntry\FlagHearingImpaired -->
            enextes(`FlagHearingImpaired', `0x55AB',
                    `type="uinteger" range="0-1" minver="4" maxOccurs="1"')

                def(`
Set to 1 if that track is suitable for users with hearing impairments, set to 0
if it is unsuitable for users with hearing impairments.
                ')

            <!-- \Segment\Tracks\TrackEntry\FlagVisualImpaired -->
            enextes(`FlagVisualImpaired', `0x55AC',
                    `type="uinteger" range="0-1" minver="4" maxOccurs="1"')

                def(`
Set to 1 if that track is suitable for users with visual impairments, set to 0
if it is unsuitable for users with visual impairments.
                ')

            <!-- \Segment\Tracks\TrackEntry\FlagTextDescriptions -->
            enextes(`FlagTextDescriptions', `0x55AD',
                    `type="uinteger" range="0-1" minver="4" maxOccurs="1"')

                def(`
Set to 1 if that track contains textual descriptions of video content, set to 0
if that track does not contain textual descriptions of video content.
                ')

            <!-- \Segment\Tracks\TrackEntry\FlagOriginal -->
            enextes(`FlagOriginal', `0x55AE',
                    `type="uinteger" range="0-1" minver="4" maxOccurs="1"')

                def(`
Set to 1 if that track is in the content's original language, set to 0 if it is
a translation.
                ')

            <!-- \Segment\Tracks\TrackEntry\FlagCommentary -->
            enextes(`FlagCommentary', `0x55AF',
                    `type="uinteger" range="0-1" minver="4" maxOccurs="1"')

                def(`
Set to 1 if that track contains commentary, set to 0 if it does not contain
commentary.
                ')

            <!-- \Segment\Tracks\TrackEntry\FlagLacing -->
            enextes(`FlagLacing', `0x9C',
                    `type="uinteger" range="0-1" default="1"' minmax(1, 1))

                def(`
Set to 1 if the track **MAY** contain blocks using lacing. When set to 0 all
blocks **MUST** have their lacing flags set to No lacing; see (#block-lacing) on
Block Lacing.
                ')
                <extension type="libmatroska" cppname="TrackFlagLacing"/>
                <extension type="webmproject.org" webm="1"/>

            <!-- \Segment\Tracks\TrackEntry\MinCache -->
            enextes(`MinCache', `0x6DE7',
                    `type="uinteger" default="0"' minmax(1, 1))

                def(`
The minimum number of frames a player **SHOULD** be able to cache during
playback. If set to 0, the reference pseudo-cache system is not used.
                ')
                <extension type="libmatroska" cppname="TrackMinCache"/>

            <!-- \Segment\Tracks\TrackEntry\MaxCache -->
            enextes(`MaxCache', `0x6DF8',
                    `type="uinteger" maxOccurs="1"')

                def(`
The maximum cache size necessary to store referenced frames in and the current
frame. 0 means no cache is needed.
                ')
                <extension type="libmatroska" cppname="TrackMaxCache"/>

            <!-- \Segment\Tracks\TrackEntry\DefaultDuration -->
            enextes(`DefaultDuration', `0x23E383',
                    `type="uinteger" range="not 0" maxOccurs="1"')

                def(`
Number of nanoseconds per frame, expressed in Matroska Ticks -- ie in
nanoseconds; see (#timestamp-ticks) (frame in the Matroska sense -- one Element
put into a (Simple)Block).
                ')
                <extension type="libmatroska" cppname="TrackDefaultDuration"/>
                <extension type="stream copy" keep="1"/>
                <extension type="webmproject.org" webm="1"/>

            <!-- \Segment\Tracks\TrackEntry\DefaultDecodedFieldDuration -->
            enextes(`DefaultDecodedFieldDuration', `0x234E7A',
                    `type="uinteger" range="not 0" minver="4" maxOccurs="1"')

                def(`
The period between two successive fields at the output of the decoding process,
expressed in Matroska Ticks -- ie in nanoseconds; see (#timestamp-ticks). see
(#defaultdecodedfieldduration) for more information
                ')
                <extension
                    type="libmatroska"
                    cppname="TrackDefaultDecodedFieldDuration"/>
                <extension type="stream copy" keep="1"/>

            <!-- \Segment\Tracks\TrackEntry\TrackTimestampScale -->
            enextes(`TrackTimestampScale', `0x23314F',
                    `type="float" range="&gt; 0x0p+0" maxver="3" default="0x1p+0"'
                    minmax(1, 1))

                def(`
DEPRECATED, DO NOT USE. The scale to apply on this track to work at normal speed
in relation with other tracks (mostly used to adjust video speed when the audio
length differs).
                ')
                <extension type="libmatroska" cppname="TrackTimecodeScale"/>
                <extension type="stream copy" keep="1"/>

            <!-- \Segment\Tracks\TrackEntry\TrackOffset -->
            enextes(`TrackOffset', `0x537F',
                    `type="integer"' minmaxver(0, 0)
                    `default="0" maxOccurs="1"')

                def(`
A value to add to the Blocks Timestamp, expressed in Matroska Ticks -- ie in
nanoseconds; see (#timestamp-ticks). This can be used to adjust the playback
offset of a track.
                ')
                <extension type="stream copy" keep="1"/>

            <!-- \Segment\Tracks\TrackEntry\MaxBlockAdditionID -->
            enextes(`MaxBlockAdditionID', `0x55EE',
                    `type="uinteger" default="0"' minmax(1, 1))

                def(`
The maximum value of BlockAddID ((#blockaddid-element)). A value 0 means there
is no BlockAdditions ((#blockadditions-element)) for this track.
                ')

            <!-- \Segment\Tracks\TrackEntry\BlockAdditionMapping -->
            enextes(`BlockAdditionMapping', `0x41E4',
                    `type="master" minver="4"')

                def(`
Contains elements that extend the track format, by adding content either to each
frame, with BlockAddID ((#blockaddid-element)), or to the track as a whole with
BlockAddIDExtraData.
                ')

                <!-- \Segment\Tracks\TrackEntry\BlockAdditionMapping
                     \BlockAddIDValue -->
                epushes(`BlockAddIDValue', `0x41F0',
                        `type="uinteger" range=">=2" minver="4" maxOccurs="1"')

                    def(`
If the track format extension needs content beside frames, the value refers to
the BlockAddID ((#blockaddid-element)), value being described. To keep
MaxBlockAdditionID as low as possible, small values **SHOULD** be used.
                    ')

                <!-- \Segment\Tracks\TrackEntry\BlockAdditionMapping
                     \BlockAddIDName -->
                enextes(`BlockAddIDName', `0x41A4',
                        `type="string" minver="4" maxOccurs="1"')

                    def(`
A human-friendly name describing the type of BlockAdditional data, as defined by
the associated Block Additional Mapping.
                    ')

                <!-- \Segment\Tracks\TrackEntry\BlockAdditionMapping
                     \BlockAddIDType -->
                enextes(`BlockAddIDType', `0x41E7',
                        `type="uinteger" minver="4" default="0"' minmax(1, 1))

                    def(`
Stores the registered identifier of the Block Additional Mapping to define how
the BlockAdditional data should be handled.
                    ')

                <!-- \Segment\Tracks\TrackEntry\BlockAdditionMapping
                     \BlockAddIDExtraData -->
                enextes(`BlockAddIDExtraData', `0x41ED',
                        `type="binary" minver="4" maxOccurs="1"')

                    def(`
Extra binary data that the BlockAddIDType can use to interpret the
BlockAdditional data. The interpretation of the binary data depends on the
BlockAddIDType value and the corresponding Block Additional Mapping.
                    ')

                epop()

            ppop()

            <!-- \Segment\Tracks\TrackEntry\Name -->
            pushes(`Name', `0x536E',
                   `type="utf-8" maxOccurs="1"')

                def(`
A human-readable track name.
                ')
                <extension type="libmatroska" cppname="TrackName"/>
                <extension type="webmproject.org" webm="1"/>

            <!-- \Segment\Tracks\TrackEntry\Language -->
            enextes(`Language', `0x22B59C',
                    `type="string" default="eng"' minmax(1, 1))

                def(`
Specifies the language of the track in the Matroska languages form; see
(#language-codes) on language codes. This Element **MUST** be ignored if the
LanguageIETF Element is used in the same TrackEntry.
                ')
                <extension type="libmatroska" cppname="TrackLanguage"/>
                <extension type="webmproject.org" webm="1"/>

            <!-- \Segment\Tracks\TrackEntry\LanguageIETF -->
            enextes(`LanguageIETF', `0x22B59D',
                    `type="string" minver="4" maxOccurs="1"')

                def(`
Specifies the language of the track according to [@!BCP47] and using the IANA
Language Subtag Registry [@!IANALangRegistry]. If this Element is used, then any
Language Elements used in the same TrackEntry **MUST** be ignored.
                ')

            <!-- \Segment\Tracks\TrackEntry\CodecID -->
            enextes(`CodecID', `0x86',
                    `type="string"' minmax(1, 1))

                def(`
An ID corresponding to the codec, see [@!MatroskaCodec] for more info.
                ')
                <extension type="stream copy" keep="1"/>
                <extension type="webmproject.org" webm="1"/>

            <!-- \Segment\Tracks\TrackEntry\CodecPrivate -->
            enextes(`CodecPrivate', `0x63A2',
                    `type="binary" maxOccurs="1"')

                def(`
Private data only known to the codec.
                ')
                <extension type="stream copy" keep="1"/>
                <extension type="webmproject.org" webm="1"/>

            <!-- \Segment\Tracks\TrackEntry\CodecName -->
            enextes(`CodecName', `0x258688',
                    `type="utf-8" maxOccurs="1"')

                def(`
A human-readable string specifying the codec.
                ')
                <extension type="webmproject.org" webm="1"/>

            <!-- \Segment\Tracks\TrackEntry\AttachmentLink -->
            enextes(`AttachmentLink', `0x7446',
                    `type="uinteger" range="not 0" maxver="3" maxOccurs="1"')

                def(`
The UID of an attachment that is used by this codec.
                ')
                usage(`
The value **MUST** match the "FileUID" value of an attachment found in this
Segment.
                ')
                <extension type="libmatroska" cppname="TrackAttachmentLink"/>

            <!-- \Segment\Tracks\TrackEntry\CodecSettings -->
            enextes(`CodecSettings', `0x3A9697',
                    `type="utf-8"' minmaxver(0, 0) `maxOccurs="1"')

                def(`
A string describing the encoding setting used.
                ')

            <!-- \Segment\Tracks\TrackEntry\CodecInfoURL -->
            enextes(`CodecInfoURL', `0x3B4040',
                    `type="string"' minmaxver(0, 0))

                def(`
A URL to find information about the codec used.
                ')

            <!-- \Segment\Tracks\TrackEntry\CodecDownloadURL -->
            enextes(`CodecDownloadURL', `0x26B240',
                    `type="string"' minmaxver(0, 0))

                def(`
A URL to download about the codec used.
                ')

            <!-- \Segment\Tracks\TrackEntry\CodecDecodeAll -->
            enextes(`CodecDecodeAll', `0xAA',
                    `type="uinteger" range="0-1" maxver="0" default="1"'
                    minmax(1, 1))

                def(`
Set to 1 if the codec can decode potentially damaged data.
                ')

            <!-- \Segment\Tracks\TrackEntry\TrackOverlay -->
            enextes(`TrackOverlay', `0x6FAB',
                    `type="uinteger"')

                def(`
Specify that this track is an overlay track for the Track specified (in the
u-integer). That means when this track has a gap, see (#silenttracks-element)
on SilentTracks, the overlay track **SHOULD** be used instead. The order of
multiple TrackOverlay matters, the first one is the one that **SHOULD** be used.
If not found it **SHOULD** be the second, etc.
                ')

            <!-- \Segment\Tracks\TrackEntry\CodecDelay -->
            enextes(`CodecDelay', `0x56AA',
                    `type="uinteger" minver="4" default="0"' minmax(1, 1))

                def(`
CodecDelay is The codec-built-in delay, expressed in Matroska Ticks -- ie in
nanoseconds; see (#timestamp-ticks). It represents the amount of codec samples
that will be discarded by the decoder during playback. This timestamp value
**MUST** be subtracted from each frame timestamp in order to get the timestamp
that will be actually played. The value **SHOULD** be small so the muxing of
tracks with the same actual timestamp are in the same Cluster.
                ')
                <extension type="webmproject.org" webm="1"/>
                <extension type="stream copy" keep="1"/>

            <!-- \Segment\Tracks\TrackEntry\SeekPreRoll -->
            enextes(`SeekPreRoll', `0x56BB',
                    `type="uinteger" minver="4" default="0"' minmax(1, 1))

                def(`
After a discontinuity, SeekPreRoll is the duration of the data the decoder
**MUST** decode before the decoded data is valid, expressed in Matroska Ticks
-- ie in nanoseconds; see (#timestamp-ticks).
                ')
                <extension type="webmproject.org" webm="1"/>
                <extension type="stream copy" keep="1"/>

            <!-- \Segment\Tracks\TrackEntry\TrackTranslate -->
            enextes(`TrackTranslate', `0x6624',
                    `type="master"')

                def(`
The mapping between this "TrackEntry" and a track value in the given Chapter
Codec.
                ')
                <documentation lang="en" purpose="rationale">
Chapter Codec may need to address content in specific track, but they may not
know of the way to identify tracks in Matroska. This element and its child
elements add a way to map the internal tracks known to the Chapter Codec to the
track IDs in Matroska. This allows remuxing a file with Chapter Codec without
changing the content of the codec data, just the track mapping.
                </documentation>

                <!-- \Segment\Tracks\TrackEntry\TrackTranslate
                     \TrackTranslateTrackID -->
                epushes(`TrackTranslateTrackID', `0x66A5',
                        `type="binary"' minmax(1, 1))

                    def(`
The binary value used to represent this "TrackEntry" in the chapter codec data.
The format depends on the "ChapProcessCodecID" used; see
(#chapprocesscodecid-element).
                    ')

                <!-- \Segment\Tracks\TrackEntry\TrackTranslate
                     \TrackTranslateCodec -->
                enextes(`TrackTranslateCodec', `0x66BF',
                        `type="uinteger"' minmax(1, 1))

                    def(`
This "TrackTranslate" applies to this chapter codec of the given chapter
edition(s); see (#chapprocesscodecid-element).
                    ')
                    <restriction>
                        enuments(0, `Matroska Script')
                            def(`
Chapter commands using the Matroska Script codec.
                            ')
                        eenuments(1, `DVD-menu')
                            def(`
Chapter commands using the DVD-like codec.
                            ')
                        enumente()
                    </restriction>

                <!-- \Segment\Tracks\TrackEntry\TrackTranslate
                     \TrackTranslateEditionUID -->
                enextes(`TrackTranslateEditionUID', `0x66FC',
                        `type="uinteger')

                    def(`
Specify a chapter edition UID on which this "TrackTranslate" applies.
                    ')
                    usage(`
When no "TrackTranslateEditionUID" is specified in the "TrackTranslate", the
"TrackTranslate" applies to all chapter editions found in the Segment using the
given "TrackTranslateCodec".
                    ')

                epop()

            ppop()

            <!-- \Segment\Tracks\TrackEntry\Video -->
            pushes(`Video', `0xE0',
                   `type="master" maxOccurs="1"')

                def(`
Video settings.
                ')
                <extension type="libmatroska" cppname="TrackVideo"/>
                <extension type="webmproject.org" webm="1"/>

                <!-- \Segment\Tracks\TrackEntry\Video\FlagInterlaced -->
                epushes(`FlagInterlaced', `0x9A',
                        `type="uinteger" minver="2" default="0"' minmax(1, 1))

                    def(`
Specify whether the video frames in this track are interlaced or not.
                    ')
                    <restriction>
                        enuments(0, `undetermined')
                            def(`
Unknown status.
                            ')
                            usage(`
This value **SHOULD** be avoided.
                            ')
                        eenuments(1, `interlaced')
                            def(`
Interlaced frames.
                            ')
                        eenuments(2, `progressive')
                            def(`
No interlacing.
                            ')
                        enumente()
                    </restriction>
                    <extension type="webmproject.org" webm="1"/>
                    <extension type="libmatroska"
                        cppname="VideoFlagInterlaced"/>
                    <extension type="stream copy" keep="1"/>

                <!-- \Segment\Tracks\TrackEntry\Video\FieldOrder -->
                enextes(`FieldOrder', `0x9D',
                        `type="uinteger" minver="4" default="2"' minmax(1, 1))

                    def(`
Specify the field ordering of video frames in this track.
                    ')
                    usage(`
If FlagInterlaced is not set to 1, this Element **MUST** be ignored.
                    ')
                    <restriction>
                        enuments(0, `progressive')
                            def(`
Interlaced frames.
                            ')
                            usage(`
This value **SHOULD** be avoided, setting FlagInterlaced to 2 is sufficient.
                            ')
                        eenuments(1, `tff')
                            def(`
Top field displayed first. Top field stored first.
                            ')
                        eenuments(2, `undetermined')
                            def(`
Unknown field order.
                            ')
                            usage(`
This value **SHOULD** be avoided.
                            ')
                        eenuments(6, `bff')
                            def(`
Bottom field displayed first. Bottom field stored first.
                            ')
                        eenuments(9, `bff(swapped)')
                            def(`
Top field displayed first. Fields are interleaved in storage with the top line
of the top field stored first.
                            ')
                        eenuments(14, `tff(swapped)')
                            def(`
Bottom field displayed first. Fields are interleaved in storage with the top
line of the top field stored first.
                            ')
                        enumente()
                    </restriction>
                    <extension type="libmatroska" cppname="VideoFieldOrder"/>
                    <extension type="stream copy" keep="1"/>

                <!-- \Segment\Tracks\TrackEntry\Video\StereoMode -->
                enextes(`StereoMode', `0x53B8',
                        `type="uinteger" minver="3" default="0"' minmax(1, 1))

                    def(`
Stereo-3D video mode. There are some more details in
(#multi-planar-and-3d-videos).
                    ')
                    <restriction>
                        enument(0, `mono')
                        enument(1, `side by side (left eye first)')
                        enument(2, `top - bottom (right eye is first)')
                        enument(3, `top - bottom (left eye is first)')
                        enument(4, `checkboard (right eye is first)')
                        enument(5, `checkboard (left eye is first)')
                        enument(6, `row interleaved (right eye is first)')
                        enument(7, `row interleaved (left eye is first)')
                        enument(8, `column interleaved (right eye is first)')
                        enument(9, `column interleaved (left eye is first)')
                        enument(10, `anaglyph (cyan/red)')
                        enument(11, `side by side (right eye first)')
                        enument(12, `anaglyph (green/magenta)')
                        enument(13,
                                `both eyes laced in one Block (left eye is first)')
                        enument(14,
                                `both eyes laced in one Block (right eye is first)')
                    </restriction>
                    <extension type="webmproject.org" webm="1"/>
                    <extension type="libmatroska" cppname="VideoStereoMode"/>
                    <extension type="stream copy" keep="1"/>

                <!-- \Segment\Tracks\TrackEntry\Video\AlphaMode -->
                enexte(`AlphaMode', `0x53C0',
                       `type="uinteger" minver="3" default="0"' minmax(1, 1))

                    def(`
Indicate whether the BlockAdditional Element with BlockAddID of "1" contains
Alpha data, as defined by to the Codec Mapping for the "CodecID". Undefined
values **SHOULD NOT** be used as the behavior of known implementations is
different (considered either as 0 or 1).
                    ')
                    <restriction>
                        enuments(0, `none')
                            def(`
The BlockAdditional Element with BlockAddID of "1" does not exist or **SHOULD
NOT** be considered as containing such data.
                            ')
                        eenuments(1, `present')
                            def(`
The BlockAdditional Element with BlockAddID of "1" contains alpha channel data.
                            ')
                        enumente()
                    </restriction>
                    <extension type="webmproject.org" webm="1"/>
                    <extension type="libmatroska" cppname="VideoAlphaMode"/>
                    <extension type="stream copy" keep="1"/>

                <!-- \Segment\Tracks\TrackEntry\Video\OldStereoMode -->
                enexte(`OldStereoMode', `0x53B9',
                       `type="uinteger" maxver="0" maxOccurs="1"')

                    def(`
DEPRECATED, DO NOT USE. Bogus StereoMode value used in old versions of
libmatroska.
                    ')
                    <restriction>
                        enument(0, `mono')
                        enument(1, `right eye')
                        enument(2, `left eye')
                        enument(3, `both eyes')
                    </restriction>

                <!-- \Segment\Tracks\TrackEntry\Video\PixelWidth -->
                enexte(`PixelWidth', `0xB0',
                       `type="uinteger" range="not 0"' minmax(1, 1))

                    def(`
Width of the encoded video frames in pixels.
                    ')
                    <extension type="libmatroska" cppname="VideoPixelWidth"/>
                    <extension type="stream copy" keep="1"/>
                    <extension type="webmproject.org" webm="1"/>

                <!-- \Segment\Tracks\TrackEntry\Video\PixelHeight -->
                enexte(`PixelHeight', `0xBA',
                       `type="uinteger" range="not 0"' minmax(1, 1))

                    def(`
Height of the encoded video frames in pixels.
                    ')
                    <extension type="libmatroska" cppname="VideoPixelHeight"/>
                    <extension type="stream copy" keep="1"/>
                    <extension type="webmproject.org" webm="1"/>

                <!-- \Segment\Tracks\TrackEntry\Video\PixelCropBottom -->
                enexte(`PixelCropBottom', `0x54AA',
                       `type="uinteger" default="0"' minmax(1, 1))

                    def(`
The number of video pixels to remove at the bottom of the image.
                    ')
                    <extension type="libmatroska"
                        cppname="VideoPixelCropBottom"/>
                    <extension type="stream copy" keep="1"/>
                    <extension type="webmproject.org" webm="1"/>

                <!-- \Segment\Tracks\TrackEntry\Video\PixelCropTop -->
                enexte(`PixelCropTop', `0x54BB',
                       `type="uinteger" default="0"' minmax(1, 1))

                    def(`
The number of video pixels to remove at the top of the image.
                    ')
                    <extension type="libmatroska" cppname="VideoPixelCropTop"/>
                    <extension type="stream copy" keep="1"/>
                    <extension type="webmproject.org" webm="1"/>

                <!-- \Segment\Tracks\TrackEntry\Video\PixelCropLeft -->
                enexte(`PixelCropLeft', `0x54CC',
                       `type="uinteger" default="0"' minmax(1, 1))

                    def(`
The number of video pixels to remove on the left of the image.
                    ')
                    <extension type="libmatroska" cppname="VideoPixelCropLeft"/>
                    <extension type="stream copy" keep="1"/>
                    <extension type="webmproject.org" webm="1"/>

                <!-- \Segment\Tracks\TrackEntry\Video\PixelCropRight -->
                enexte(`PixelCropRight', `0x54DD',
                       `type="uinteger" default="0"' minmax(1, 1))

                    def(`
The number of video pixels to remove on the right of the image.
                    ')
                    <extension type="libmatroska"
                        cppname="VideoPixelCropRight"/>
                    <extension type="stream copy" keep="1"/>
                    <extension type="webmproject.org" webm="1"/>

                <!-- \Segment\Tracks\TrackEntry\Video\DisplayWidth -->
                enextes(`DisplayWidth', `0x54B0',
                        `type="uinteger" range="not 0" maxOccurs="1"')

                    def(`
Width of the video frames to display. Applies to the video frame after cropping
(PixelCrop* Elements).
                    ')
                    <implementation_note note_attribute="default">
If the DisplayUnit of the same TrackEntry is 0, then the default value for
DisplayWidth is equal to PixelWidth - PixelCropLeft - PixelCropRight, else there
is no default value.
                    </implementation_note>
                    <extension type="libmatroska" cppname="VideoDisplayWidth"/>
                    <extension type="stream copy" keep="1"/>
                    <extension type="webmproject.org" webm="1"/>

                <!-- \Segment\Tracks\TrackEntry\Video\DisplayHeight -->
                enextes(`DisplayHeight', `0x54BA',
                        `type="uinteger" range="not 0" maxOccurs="1"')

                    def(`
Height of the video frames to display. Applies to the video frame after cropping
(PixelCrop* Elements).
                    ')
                    <implementation_note note_attribute="default">
If the DisplayUnit of the same TrackEntry is 0, then the default value for
DisplayHeight is equal to PixelHeight - PixelCropTop - PixelCropBottom, else
there is no default value.
                    </implementation_note>
                    <extension type="libmatroska" cppname="VideoDisplayHeight"/>
                    <extension type="stream copy" keep="1"/>
                    <extension type="webmproject.org" webm="1"/>

                <!-- \Segment\Tracks\TrackEntry\Video\DisplayUnit -->
                enextes(`DisplayUnit', `0x54B2',
                        `type="uinteger" default="0"' minmax(1, 1))

                    def(`
How DisplayWidth &amp; DisplayHeight are interpreted.
                    ')
                    <restriction>
                        enument(0, `pixels')
                        enument(1, `centimeters')
                        enument(2, `inches')
                        enument(3, `display aspect ratio')
                        enument(4, `unknown')
                    </restriction>
                    <extension type="libmatroska" cppname="VideoDisplayUnit"/>
                    <extension type="webmproject.org" webm="1"/>

                <!-- \Segment\Tracks\TrackEntry\Video\AspectRatioType -->
                enextes(`AspectRatioType', `0x54B3',
                        `type="uinteger"' minmaxver(0, 0)
                        `default="0" maxOccurs="1"')

                    def(`
Specify the possible modifications to the aspect ratio.
                    ')
                    <restriction>
                        enument(0, `free resizing')
                        enument(1, `keep aspect ratio')
                        enument(2, `fixed')
                    </restriction>
                    <extension type="libmatroska" cppname="VideoAspectRatio"/>

                <!-- \Segment\Tracks\TrackEntry\Video\UncompressedFourCC -->
                enextes(`UncompressedFourCC', `0x2EB524',
                        `type="binary" length="4" maxOccurs="1"')

                    def(`
Specify the uncompressed pixel format used for the Tracks data as a FourCC.
This value is similar in scope to the biCompression value of AVIs "BITMAPINFO"
[@?AVIFormat]. See the YUV video formats [@?FourCC-YUV] and RGB video formats
[@?FourCC-RGB] for common values.
                    ')
                    <implementation_note note_attribute="minOccurs">
UncompressedFourCC **MUST** be set (minOccurs=1) in TrackEntry, when the
CodecID Element of the TrackEntry is set to "V_UNCOMPRESSED".
                    </implementation_note>
                    usage(`
This Element **MUST NOT** be used if the CodecID Element of the TrackEntry is
set to "V_UNCOMPRESSED".
                    ')
                    <extension type="libmatroska" cppname="VideoColourSpace"/>
                    <extension type="stream copy" keep="1"/>

                <!-- \Segment\Tracks\TrackEntry\Video\GammaValue -->
                enextes(`GammaValue', `0x2FB523',
                        `type="float" range="&gt; 0x0p+0"' minmaxver(0, 0)
                        `maxOccurs="1"')

                    def(`
Gamma Value.
                    ')
                    <extension type="libmatroska" cppname="VideoGamma"/>

                <!-- \Segment\Tracks\TrackEntry\Video\FrameRate -->
                enextes(`FrameRate', `0x2383E3',
                        `type="float" range="&gt; 0x0p+0"' minmaxver(0, 0)
                        `maxOccurs="1"')

                    def(`
Number of frames per second. This value is Informational only. It is intended
for constant frame rate streams, and **SHOULD NOT** be used for a variable
frame rate TrackEntry.
                    ')
                    <extension type="libmatroska" cppname="VideoFrameRate"/>

                <!-- \Segment\Tracks\TrackEntry\Video\Colour -->
                enextes(`Colour', `0x55B0',
                        `type="master" minver="4" maxOccurs="1"')

                    def(`
Settings describing the colour format.
                    ')
                    <extension type="webmproject.org" webm="1"/>
                    <extension type="libmatroska" cppname="VideoColour"/>
                    <extension type="stream copy" keep="1"/>

                    <!-- \Segment\Tracks\TrackEntry\Video\Colour
                         \MatrixCoefficients -->
                    epushes(`MatrixCoefficients', `0x55B1',
                            `type="uinteger" minver="4" default="2"'
                            minmax(1, 1))

                        def(`
The Matrix Coefficients of the video used to derive luma and chroma values from
red, green, and blue color primaries. For clarity, the value and meanings for
MatrixCoefficients are adopted from Table 4 of ISO/IEC 23001-8:2016 or ITU-T
H.273.
                        ')
                        <restriction>
                            enument(0, `Identity')
                            enument(1, `ITU-R BT.709')
                            enument(2, `unspecified')
                            enument(3, `reserved')
                            enument(4, `US FCC 73.682')
                            enument(5, `ITU-R BT.470BG')
                            enument(6, `SMPTE 170M')
                            enument(7, `SMPTE 240M')
                            enument(8, `YCoCg')
                            enument(9, `BT2020 Non-constant Luminance')
                            enument(10, `BT2020 Constant Luminance')
                            enument(11, `SMPTE ST 2085')
                            enument(12, `Chroma-derived Non-constant Luminance')
                            enument(13, `Chroma-derived Constant Luminance')
                            enument(14, `ITU-R BT.2100-0')
                        </restriction>
                        <extension type="webmproject.org" webm="1"/>
                        <extension type="libmatroska"
                            cppname="VideoColourMatrix"/>
                        <extension type="stream copy" keep="1"/>

                    <!-- \Segment\Tracks\TrackEntry\Video\Colour
                         \BitsPerChannel -->
                    enextes(`BitsPerChannel', `0x55B2',
                            `type="uinteger" minver="4" default="0"'
                            minmax(1, 1))

                        def(`
Number of decoded bits per channel. A value of 0 indicates that the
BitsPerChannel is unspecified.
                        ')
                        <extension type="webmproject.org" webm="1"/>
                        <extension type="libmatroska"
                            cppname="VideoBitsPerChannel"/>
                        <extension type="stream copy" keep="1"/>

                    <!-- \Segment\Tracks\TrackEntry\Video\Colour
                         \ChromaSubsamplingHorz -->
                    enextes(`ChromaSubsamplingHorz', `0x55B3',
                            `type="uinteger" minver="4" maxOccurs="1"')

                        def(`
The amount of pixels to remove in the Cr and Cb channels for every pixel not
removed horizontally. Example: For video with 4:2:0 chroma subsampling, the
ChromaSubsamplingHorz **SHOULD** be set to 1.
                        ')
                        <extension type="webmproject.org" webm="1"/>
                        <extension type="libmatroska"
                            cppname="VideoChromaSubsampHorz"/>
                        <extension type="stream copy" keep="1"/>

                    <!-- \Segment\Tracks\TrackEntry\Video\Colour
                         \ChromaSubsamplingVert -->
                    enextes(`ChromaSubsamplingVert', `0x55B4',
                            `type="uinteger" minver="4" maxOccurs="1"')

                        def(`
The amount of pixels to remove in the Cr and Cb channels for every pixel not
removed vertically. Example: For video with 4:2:0 chroma subsampling, the
ChromaSubsamplingVert **SHOULD** be set to 1.
                        ')
                        <extension type="webmproject.org" webm="1"/>
                        <extension type="libmatroska"
                            cppname="VideoChromaSubsampVert"/>
                        <extension type="stream copy" keep="1"/>

                    <!-- \Segment\Tracks\TrackEntry\Video\Colour
                         \CbSubsamplingHorz -->
                    enextes(`CbSubsamplingHorz', `0x55B5',
                            `type="uinteger" minver="4" maxOccurs="1"')

                        def(`
The amount of pixels to remove in the Cb channel for every pixel not removed
horizontally. This is additive with ChromaSubsamplingHorz. Example: For video
with 4:2:1 chroma subsampling, the ChromaSubsamplingHorz **SHOULD** be set to 1
and CbSubsamplingHorz **SHOULD** be set to 1.
                        ')
                        <extension type="webmproject.org" webm="1"/>
                        <extension type="libmatroska"
                            cppname="VideoCbSubsampHorz"/>
                        <extension type="stream copy" keep="1"/>

                    <!-- \Segment\Tracks\TrackEntry\Video\Colour
                         \CbSubsamplingVert -->
                    enextes(`CbSubsamplingVert', `0x55B6',
                            `type="uinteger" minver="4" maxOccurs="1"')

                        def(`
The amount of pixels to remove in the Cb channel for every pixel not removed
vertically. This is additive with ChromaSubsamplingVert.
                        ')
                        <extension type="webmproject.org" webm="1"/>
                        <extension type="libmatroska"
                            cppname="VideoCbSubsampVert"/>
                        <extension type="stream copy" keep="1"/>

                    <!-- \Segment\Tracks\TrackEntry\Video\Colour
                         \ChromaSitingHorz -->
                    enextes(`ChromaSitingHorz', `0x55B7',
                            `type="uinteger" minver="4" default="0"'
                            minmax(1, 1))

                        def(`
How chroma is subsampled horizontally.
                        ')
                        <restriction>
                            enument(0, `unspecified')
                            enument(1, `left collocated')
                            enument(2, `half')
                        </restriction>
                        <extension type="webmproject.org" webm="1"/>
                        <extension type="libmatroska"
                            cppname="VideoChromaSitHorz"/>
                        <extension type="stream copy" keep="1"/>

                    <!-- \Segment\Tracks\TrackEntry\Video\Colour
                         \ChromaSitingVert -->
                    enextes(`ChromaSitingVert', `0x55B8',
                            `type="uinteger" minver="4" default="0"'
                            minmax(1, 1))

                        def(`
How chroma is subsampled vertically.
                        ')
                        <restriction>
                            enument(0, `unspecified')
                            enument(1, `top collocated')
                            enument(2, `half')
                        </restriction>
                        <extension type="webmproject.org" webm="1"/>
                        <extension type="libmatroska"
                            cppname="VideoChromaSitVert"/>
                        <extension type="stream copy" keep="1"/>

                    <!-- \Segment\Tracks\TrackEntry\Video\Colour\Range -->
                    enextes(`Range', `0x55B9',
                            `type="uinteger" minver="4" default="0"'
                            minmax(1, 1))

                        def(`
Clipping of the color ranges.
                        ')
                        <restriction>
                            enument(0, `unspecified')
                            enument(1, `broadcast range')
                            enument(2, `full range (no clipping)')
                            enument(3,
                                    `defined by MatrixCoefficients / TransferCharacteristics')
                        </restriction>
                        <extension type="webmproject.org" webm="1"/>
                        <extension type="libmatroska"
                            cppname="VideoColourRange"/>
                        <extension type="stream copy" keep="1"/>

                    <!-- \Segment\Tracks\TrackEntry\Video\Colour
                         \TransferCharacteristics -->
                    enextes(`TransferCharacteristics', `0x55BA',
                            `type="uinteger" minver="4" default="2"'
                            minmax(1, 1))

                        def(`
The transfer characteristics of the video. For clarity, the value and meanings
for TransferCharacteristics are adopted from Table 3 of ISO/IEC 23091-4 or
ITU-T H.273.
                        ')
                        <restriction>
                            enument(0, `reserved')
                            enument(1, `ITU-R BT.709')
                            enument(2, `unspecified')
                            enument(3, `reserved')
                            enument(4, `Gamma 2.2 curve - BT.470M')
                            enument(5, `Gamma 2.8 curve - BT.470BG')
                            enument(6, `SMPTE 170M')
                            enument(7, `SMPTE 240M')
                            enument(8, `Linear')
                            enument(9, `Log')
                            enument(10, `Log Sqrt')
                            enument(11, `IEC 61966-2-4')
                            enument(12, `ITU-R BT.1361 Extended Colour Gamut')
                            enument(13, `IEC 61966-2-1')
                            enument(14, `ITU-R BT.2020 10 bit')
                            enument(15, `ITU-R BT.2020 12 bit')
                            enument(16, `ITU-R BT.2100 Perceptual Quantization')
                            enument(17, `SMPTE ST 428-1')
                            enument(18, `ARIB STD-B67 (HLG)')
                        </restriction>
                        <extension type="webmproject.org" webm="1"/>
                        <extension type="libmatroska"
                            cppname="VideoColourTransferCharacter"/>
                        <extension type="stream copy" keep="1"/>

                    <!-- \Segment\Tracks\TrackEntry\Video\Colour\Primaries -->
                    enextes(`Primaries', `0x55BB',
                            `type="uinteger" minver="4" default="2"'
                            minmax(1, 1))

                        def(`
The colour primaries of the video. For clarity, the value and meanings for
Primaries are adopted from Table 2 of ISO/IEC 23091-4 or ITU-T H.273.
                        ')
                        <restriction>
                            enument(0, `reserved')
                            enument(1, `ITU-R BT.709')
                            enument(2, `unspecified')
                            enument(3, `reserved')
                            enument(4, `ITU-R BT.470M')
                            enument(5, `ITU-R BT.470BG - BT.601 625')
                            enument(6, `ITU-R BT.601 525 - SMPTE 170M')
                            enument(7, `SMPTE 240M')
                            enument(8, `FILM')
                            enument(9, `ITU-R BT.2020')
                            enument(10, `SMPTE ST 428-1')
                            enument(11, `SMPTE RP 432-2')
                            enument(12, `SMPTE EG 432-2')
                            enument(22,
                                    `EBU Tech. 3213-E - JEDEC P22 phosphors')
                        </restriction>
                        <extension type="webmproject.org" webm="1"/>
                        <extension type="libmatroska"
                            cppname="VideoColourPrimaries"/>
                        <extension type="stream copy" keep="1"/>

                    <!-- \Segment\Tracks\TrackEntry\Video\Colour\MaxCLL -->
                    enextes(`MaxCLL', `0x55BC',
                            `type="uinteger" minver="4" maxOccurs="1"')

                        def(`
Maximum brightness of a single pixel (Maximum Content Light Level) in candelas
per square meter (cd/m^2^).
                        ')
                        <extension type="webmproject.org" webm="1"/>
                        <extension type="libmatroska"
                            cppname="VideoColourMaxCLL"/>
                        <extension type="stream copy" keep="1"/>

                    <!-- \Segment\Tracks\TrackEntry\Video\Colour\MaxFALL -->
                    enextes(`MaxFALL', `0x55BD',
                            `type="uinteger" minver="4" maxOccurs="1"')

                        def(`
Maximum brightness of a single full frame (Maximum Frame-Average Light Level) in
candelas per square meter (cd/m^2^).
                        ')
                        <extension type="webmproject.org" webm="1"/>
                        <extension type="libmatroska"
                            cppname="VideoColourMaxFALL"/>
                        <extension type="stream copy" keep="1"/>

                    <!-- \Segment\Tracks\TrackEntry\Video\Colour
                         \MasteringMetadata -->
                    enextes(`MasteringMetadata', `0x55D0',
                            `type="master" minver="4" maxOccurs="1"')

                        def(`
SMPTE 2086 mastering data.
                        ')
                        <extension type="webmproject.org" webm="1"/>
                        <extension type="libmatroska"
                            cppname="VideoColourMasterMeta"/>
                        <extension type="stream copy" keep="1"/>

                        <!-- \Segment\Tracks\TrackEntry\Video\Colour
                             \MasteringMetadata\PrimaryRChromaticityX -->
                        epushes(`PrimaryRChromaticityX', `0x55D1',
                                `type="float" range="0-1" minver="4" maxOccurs="1"')

                            def(`
Red X chromaticity coordinate, as defined by CIE 1931.
                            ')
                            <extension type="webmproject.org" webm="1"/>
                            <extension type="libmatroska"
                                cppname="VideoRChromaX"/>
                            <extension type="stream copy" keep="1"/>

                        <!-- \Segment\Tracks\TrackEntry\Video\Colour
                             \MasteringMetadata\PrimaryRChromaticityY -->
                        enextes(`PrimaryRChromaticityY', `0x55D2',
                                `type="float" range="0-1" minver="4" maxOccurs="1"')

                            def(`
Red Y chromaticity coordinate, as defined by CIE 1931.
                            ')
                            <extension type="webmproject.org" webm="1"/>
                            <extension type="libmatroska"
                                cppname="VideoRChromaY"/>
                            <extension type="stream copy" keep="1"/>

                        <!-- \Segment\Tracks\TrackEntry\Video\Colour
                             \MasteringMetadata\PrimaryGChromaticityX -->
                        enextes(`PrimaryGChromaticityX', `0x55D3',
                                `type="float" range="0-1" minver="4" maxOccurs="1"')

                            def(`
Green X chromaticity coordinate, as defined by CIE 1931.
                            ')
                            <extension type="webmproject.org" webm="1"/>
                            <extension type="libmatroska"
                                cppname="VideoGChromaX"/>
                            <extension type="stream copy" keep="1"/>

                        <!-- \Segment\Tracks\TrackEntry\Video\Colour
                             \MasteringMetadata\PrimaryGChromaticityY -->
                        enextes(`PrimaryGChromaticityY', `0x55D4',
                                `type="float" range="0-1" minver="4" maxOccurs="1"')

                            def(`
Green Y chromaticity coordinate, as defined by CIE 1931.
                            ')
                            <extension type="webmproject.org" webm="1"/>
                            <extension type="libmatroska"
                                cppname="VideoGChromaY"/>
                            <extension type="stream copy" keep="1"/>

                        <!-- \Segment\Tracks\TrackEntry\Video\Colour
                             \MasteringMetadata\PrimaryBChromaticityX -->
                        enextes(`PrimaryBChromaticityX', `0x55D5',
                                `type="float" range="0-1" minver="4" maxOccurs="1"')

                            def(`
Blue X chromaticity coordinate, as defined by CIE 1931.
                            ')
                            <extension type="webmproject.org" webm="1"/>
                            <extension type="libmatroska"
                                cppname="VideoBChromaX"/>
                            <extension type="stream copy" keep="1"/>

                        <!-- \Segment\Tracks\TrackEntry\Video\Colour
                             \MasteringMetadata\PrimaryBChromaticityY -->
                        enextes(`PrimaryBChromaticityY', `0x55D6',
                                `type="float" range="0-1" minver="4" maxOccurs="1"')

                            def(`
Blue Y chromaticity coordinate, as defined by CIE 1931.
                            ')
                            <extension type="webmproject.org" webm="1"/>
                            <extension type="libmatroska"
                                cppname="VideoBChromaY"/>
                            <extension type="stream copy" keep="1"/>

                        <!-- \Segment\Tracks\TrackEntry\Video\Colour
                             \MasteringMetadata\WhitePointChromaticityX -->
                        enextes(`WhitePointChromaticityX', `0x55D7',
                                `type="float" range="0-1" minver="4" maxOccurs="1"')

                            def(`
White X chromaticity coordinate, as defined by CIE 1931.
                            ')
                            <extension type="webmproject.org" webm="1"/>
                            <extension type="libmatroska"
                                cppname="VideoWhitePointChromaX"/>
                            <extension type="stream copy" keep="1"/>

                        <!-- \Segment\Tracks\TrackEntry\Video\Colour
                             \MasteringMetadata\WhitePointChromaticityY -->
                        enextes(`WhitePointChromaticityY', `0x55D8',
                                `type="float" range="0-1" minver="4" maxOccurs="1"')

                            def(`
White Y chromaticity coordinate, as defined by CIE 1931.
                            ')
                            <extension type="webmproject.org" webm="1"/>
                            <extension type="libmatroska"
                                cppname="VideoWhitePointChromaY"/>
                            <extension type="stream copy" keep="1"/>

                        <!-- \Segment\Tracks\TrackEntry\Video\Colour
                             \MasteringMetadata\LuminanceMax -->
                        enextes(`LuminanceMax', `0x55D9',
                                `type="float" range="&gt;= 0x0p+0" minver="4" maxOccurs="1"')

                            def(`
Maximum luminance. Represented in candelas per square meter (cd/m^2^).
                            ')
                            <extension type="webmproject.org" webm="1"/>
                            <extension type="libmatroska"
                                cppname="VideoLuminanceMax"/>
                            <extension type="stream copy" keep="1"/>

                        <!-- \Segment\Tracks\TrackEntry\Video\Colour
                             \MasteringMetadata\LuminanceMin -->
                        enextes(`LuminanceMin', `0x55DA',
                                `type="float" range="&gt;= 0x0p+0" minver="4" maxOccurs="1"')

                            def(`
Minimum luminance. Represented in candelas per square meter (cd/m^2^).
                            ')
                            <extension type="webmproject.org" webm="1"/>
                            <extension type="libmatroska"
                                cppname="VideoLuminanceMin"/>
                            <extension type="stream copy" keep="1"/>

                        epop()

                    ppop()

                ppop()

                <!-- \Segment\Tracks\TrackEntry\Video\Projection -->
                pushes(`Projection', `0x7670',
                       `type="master" minver="4" maxOccurs="1"')

                    def(`
Describes the video projection details. Used to render spherical, VR videos or
flipping videos horizontally/vertically.
                    ')
                    <extension type="webmproject.org" webm="1"/>
                    <extension type="libmatroska" cppname="VideoProjection"/>
                    <extension type="stream copy" keep="1"/>

                    <!-- \Segment\Tracks\TrackEntry\Video\Projection
                         \ProjectionType -->
                    epushes(`ProjectionType', `0x7671',
                            `type="uinteger" minver="4" default="0"'
                            minmax(1, 1))

                        def(`
Describes the projection used for this video track.
                        ')
                        <restriction>
                            enument(0, `rectangular')
                            enument(1, `equirectangular')
                            enument(2, `cubemap')
                            enument(3, `mesh')
                        </restriction>
                        <extension type="webmproject.org" webm="1"/>
                        <extension type="libmatroska"
                            cppname="VideoProjectionType"/>
                        <extension type="stream copy" keep="1"/>

                    <!-- \Segment\Tracks\TrackEntry\Video\Projection
                         \ProjectionPrivate -->
                    enextes(`ProjectionPrivate', `0x7672',
                            `type="binary" minver="4" maxOccurs="1"')

                        def(`
Private data that only applies to a specific projection.

*  If "ProjectionType" equals 0 (Rectangular),
     then this element must not be present.
*  If "ProjectionType" equals 1 (Equirectangular), then this element must be present and contain the same binary data that would be stored inside
      an ISOBMFF Equirectangular Projection Box ("equi").
*  If "ProjectionType" equals 2 (Cubemap), then this element must be present and contain the same binary data that would be stored
      inside an ISOBMFF Cubemap Projection Box ("cbmp").
*  If "ProjectionType" equals 3 (Mesh), then this element must be present and contain the same binary data that would be stored inside
       an ISOBMFF Mesh Projection Box ("mshp").
                        ')
                        usage(`
ISOBMFF box size and fourcc fields are not included in the binary data, but the
FullBox version and flag fields are. This is to avoid redundant framing
information while preserving versioning and semantics between the two container
formats.
                        ')
                        <extension type="webmproject.org" webm="1"/>
                        <extension type="libmatroska"
                            cppname="VideoProjectionPrivate"/>
                        <extension type="stream copy" keep="1"/>

                    <!-- \Segment\Tracks\TrackEntry\Video\Projection
                         \ProjectionPoseYaw -->
                    enextes(`ProjectionPoseYaw', `0x7673',
                            `type="float" range="&gt;= -0xB4p+0, &lt;= 0xB4p+0" minver="4" default="0x0p+0"'
                            minmax(1, 1))

                        def(`
Specifies a yaw rotation to the projection.

Value represents a clockwise rotation, in degrees, around the up vector. This
rotation must be applied before any "ProjectionPosePitch" or
"ProjectionPoseRoll" rotations. The value of this element **MUST** be in the
-180 to 180 degree range, both included.

Setting "ProjectionPoseYaw" to 180 or -180 degrees, with the
"ProjectionPoseRoll" and "ProjectionPosePitch" set to 0 degrees flips the image
horizontally.
                        ')
                        <extension type="webmproject.org" webm="1"/>
                        <extension type="libmatroska"
                            cppname="VideoProjectionPoseYaw"/>
                        <extension type="stream copy" keep="1"/>

                    <!-- \Segment\Tracks\TrackEntry\Video\Projection
                         \ProjectionPosePitch -->
                    enextes(`ProjectionPosePitch', `0x7674',
                            `type="float" range="&gt;= -0x5Ap+0, &lt;= 0x5Ap+0" minver="4" default="0x0p+0"'
                            minmax(1, 1))

                        def(`
Specifies a pitch rotation to the projection.

Value represents a counter-clockwise rotation, in degrees, around the right
vector. This rotation must be applied after the "ProjectionPoseYaw" rotation and
before the "ProjectionPoseRoll" rotation. The value of this element **MUST** be
in the -90 to 90 degree range, both included.
                        ')
                        <extension type="webmproject.org" webm="1"/>
                        <extension type="libmatroska"
                            cppname="VideoProjectionPosePitch"/>
                        <extension type="stream copy" keep="1"/>

                    <!-- \Segment\Tracks\TrackEntry\Video\Projection
                         \ProjectionPoseRoll -->
                    enextes(`ProjectionPoseRoll', `0x7675',
                            `type="float" range="&gt;= -0xB4p+0, &lt;= 0xB4p+0" minver="4" default="0x0p+0"'
                            minmax(1, 1))

                        def(`
Specifies a roll rotation to the projection.

Value represents a counter-clockwise rotation, in degrees, around the forward
vector. This rotation must be applied after the "ProjectionPoseYaw" and
"ProjectionPosePitch" rotations. The value of this element **MUST** be in the
-180 to 180 degree range, both included.

Setting "ProjectionPoseRoll" to 180 or -180 degrees, the "ProjectionPoseYaw" to
180 or -180 degrees with "ProjectionPosePitch" set to 0 degrees flips the image
vertically.

Setting "ProjectionPoseRoll" to 180 or -180 degrees, with the
"ProjectionPoseYaw" and "ProjectionPosePitch" set to 0 degrees flips the image
horizontally and vertically.
                        ')
                        <extension type="webmproject.org" webm="1"/>
                        <extension type="libmatroska"
                            cppname="VideoProjectionPoseRoll"/>
                        <extension type="stream copy" keep="1"/>

                    epop()

                ppop()

            ppop()

            <!-- \Segment\Tracks\TrackEntry\Audio -->
            pushes(`Audio', `0xE1',
                   `type="master" maxOccurs="1"')

                def(`
Audio settings.
                ')
                <extension type="libmatroska" cppname="TrackAudio"/>
                <extension type="webmproject.org" webm="1"/>

                <!-- \Segment\Tracks\TrackEntry\Audio\SamplingFrequency -->
                epushes(`SamplingFrequency', `0xB5',
                        `type="float" range="&gt; 0x0p+0" default="0x1.f4p+12"'
                        minmax(1, 1))

                    def(`
Sampling frequency in Hz.
                    ')
                    <extension type="libmatroska" cppname="AudioSamplingFreq"/>
                    <extension type="stream copy" keep="1"/>
                    <extension type="webmproject.org" webm="1"/>

                <!-- \Segment\Tracks\TrackEntry\Audio
                     \OutputSamplingFrequency -->
                enextes(`OutputSamplingFrequency', `0x78B5',
                        `type="float" range="&gt; 0x0p+0" maxOccurs="1"')

                    def(`
Real output sampling frequency in Hz (used for SBR techniques).
                    ')
                    <implementation_note note_attribute="default">
The default value for OutputSamplingFrequency of the same TrackEntry is equal to
the SamplingFrequency.
                    </implementation_note>
                    <extension type="libmatroska"
                        cppname="AudioOutputSamplingFreq"/>
                    <extension type="webmproject.org" webm="1"/>

                <!-- \Segment\Tracks\TrackEntry\Audio\Channels -->
                enextes(`Channels', `0x9F',
                        `type="uinteger" range="not 0" default="1"'
                        minmax(1, 1))

                    def(`
Numbers of channels in the track.
                    ')
                    <extension type="libmatroska" cppname="AudioChannels"/>
                    <extension type="stream copy" keep="1"/>
                    <extension type="webmproject.org" webm="1"/>

                <!-- \Segment\Tracks\TrackEntry\Audio\ChannelPositions -->
                enextes(`ChannelPositions', `0x7D7B',
                        `type="binary"' minmaxver(0, 0) `maxOccurs="1"')

                    def(`
Table of horizontal angles for each successive channel.
                    ')
                    <extension type="libmatroska" cppname="AudioPosition"/>

                <!-- \Segment\Tracks\TrackEntry\Audio\BitDepth -->
                enextes(`BitDepth', `0x6264',
                        `type="uinteger" range="not 0" maxOccurs="1"')

                    def(`
Bits per sample, mostly used for PCM.
                    ')
                    <extension type="libmatroska" cppname="AudioBitDepth"/>
                    <extension type="stream copy" keep="1"/>
                    <extension type="webmproject.org" webm="1"/>

                epop()

            ppop()

            <!-- \Segment\Tracks\TrackEntry\TrackOperation -->
            pushes(`TrackOperation', `0xE2',
                   `type="master" minver="3" maxOccurs="1"')

                def(`
Operation that needs to be applied on tracks to create this virtual track. For
more details look at (#track-operation).
                ')
                <extension type="stream copy" keep="1"/>

                <!-- \Segment\Tracks\TrackEntry\TrackOperation
                     \TrackCombinePlanes -->
                epushes(`TrackCombinePlanes', `0xE3',
                        `type="master" minver="3" maxOccurs="1"')

                    def(`
Contains the list of all video plane tracks that need to be combined to create
this 3D track
                    ')
                    <extension type="stream copy" keep="1"/>

                    <!-- \Segment\Tracks\TrackEntry\TrackOperation
                         \TrackCombinePlanes\TrackPlane -->
                    epushes(`TrackPlane', `0xE4',
                            `type="master" minver="3" minOccurs="1"')

                        def(`
Contains a video plane track that need to be combined to create this 3D track
                        ')
                        <extension type="stream copy" keep="1"/>

                        <!-- \Segment\Tracks\TrackEntry\TrackOperation
                             \TrackCombinePlanes\TrackPlane\TrackPlaneUID -->
                        epushes(`TrackPlaneUID', `0xE5',
                                `type="uinteger" range="not 0" minver="3"'
                                minmax(1, 1))

                            def(`
The trackUID number of the track representing the plane.
                            ')
                            <extension type="stream copy" keep="1"/>

                        <!-- \Segment\Tracks\TrackEntry\TrackOperation
                             \TrackCombinePlanes\TrackPlane\TrackPlaneType -->
                        enextes(`TrackPlaneType', `0xE6',
                                `type="uinteger" minver="3"' minmax(1, 1))

                            def(`
The kind of plane this track corresponds to.
                            ')
                            <restriction>
                                enument(0, `left eye')
                                enument(1, `right eye')
                                enument(2, `background')
                            </restriction>
                            <extension type="stream copy" keep="1"/>

                        epop()

                    ppop()

                ppop()

                <!-- \Segment\Tracks\TrackEntry\TrackOperation
                     \TrackJoinBlocks -->
                pushes(`TrackJoinBlocks', `0xE9',
                       `type="master" minver="3" maxOccurs="1"')

                    def(`
Contains the list of all tracks whose Blocks need to be combined to create this
virtual track
                    ')
                    <extension type="stream copy" keep="1"/>

                    <!-- \Segment\Tracks\TrackEntry\TrackOperation
                         \TrackJoinBlocks\TrackJoinUID -->
                    epushes(`TrackJoinUID', `0xED',
                            `type="uinteger" range="not 0" minver="3" minOccurs="1"')

                        def(`
The trackUID number of a track whose blocks are used to create this virtual
track.
                        ')
                        <extension type="stream copy" keep="1"/>

                    epop()

                ppop()

            ppop()

            <!-- \Segment\Tracks\TrackEntry\TrickTrackUID -->
            pushes(`TrickTrackUID', `0xC0',
                   `type="uinteger"' minmaxver(0, 0) `maxOccurs="1"')

                def(`
The TrackUID of the Smooth FF/RW video in the paired EBML structure
corresponding to this video track. See [@?DivXTrickTrack].
                ')
                <extension type="divx.com" divx="1"/>

            <!-- \Segment\Tracks\TrackEntry\TrickTrackSegmentUID -->
            enextes(`TrickTrackSegmentUID', `0xC1',
                    `type="binary" length="16"' minmaxver(0, 0) `maxOccurs="1"')

                def(`
The SegmentUID of the Segment containing the track identified by TrickTrackUID.
See [@?DivXTrickTrack].
                ')
                <extension type="divx.com" divx="1"/>

            <!-- \Segment\Tracks\TrackEntry\TrickTrackFlag -->
            enextes(`TrickTrackFlag', `0xC6',
                    `type="uinteger"' minmaxver(0, 0)
                    `default="0" maxOccurs="1"')

                def(`
Set to 1 if this video track is a Smooth FF/RW track. If set to 1,
MasterTrackUID and MasterTrackSegUID should must be present and BlockGroups for
this track must contain ReferenceFrame structures. Otherwise, TrickTrackUID and
TrickTrackSegUID must be present if this track has a corresponding Smooth FF/RW
track. See [@?DivXTrickTrack].
                ')
                <extension type="divx.com" divx="1"/>

            <!-- \Segment\Tracks\TrackEntry\TrickMasterTrackUID -->
            enextes(`TrickMasterTrackUID', `0xC7',
                    `type="uinteger"' minmaxver(0, 0) `maxOccurs="1"')

                def(`
The TrackUID of the video track in the paired EBML structure that corresponds to
this Smooth FF/RW track. See [@?DivXTrickTrack].
                ')
                <extension type="divx.com" divx="1"/>

            <!-- \Segment\Tracks\TrackEntry\TrickMasterTrackSegmentUID -->
            enextes(`TrickMasterTrackSegmentUID', `0xC4',
                    `type="binary" length="16"' minmaxver(0, 0) `maxOccurs="1"')

                def(`
The SegmentUID of the Segment containing the track identified by MasterTrackUID.
See [@?DivXTrickTrack].
                ')
                <extension type="divx.com" divx="1"/>

            epop()

            <!-- \Segment\Tracks\TrackEntry\ContentEncodings -->
            pushes(`ContentEncodings', `0x6D80',
                   `type="master" maxOccurs="1"')

                def(`
Settings for several content encoding mechanisms like compression or encryption.
                ')
                <extension type="webmproject.org" webm="1"/>
                <extension type="stream copy" keep="1"/>

                <!-- \Segment\Tracks\TrackEntry\ContentEncodings
                     \ContentEncoding -->
                epushes(`ContentEncoding', `0x6240',
                        `type="master" minOccurs="1"')

                    def(`
Settings for one content encoding like compression or encryption.
                    ')
                    <extension type="webmproject.org" webm="1"/>
                    <extension type="stream copy" keep="1"/>

                    <!-- \Segment\Tracks\TrackEntry\ContentEncodings
                         \ContentEncoding\ContentEncodingOrder -->
                    epushes(`ContentEncodingOrder', `0x5031',
                            `type="uinteger" default="0"' minmax(1, 1))

                        def(`
Tell in which order to apply each "ContentEncoding" of the "ContentEncodings".
The decoder/demuxer **MUST** start with the "ContentEncoding" with the highest
"ContentEncodingOrder" and work its way down to the "ContentEncoding" with the
lowest "ContentEncodingOrder". This value **MUST** be unique over for each
"ContentEncoding" found in the "ContentEncodings" of this "TrackEntry".
                        ')
                        <extension type="webmproject.org" webm="1"/>
                        <extension type="stream copy" keep="1"/>

                    <!-- \Segment\Tracks\TrackEntry\ContentEncodings
                         \ContentEncoding\ContentEncodingScope -->
                    enextes(`ContentEncodingScope', `0x5032',
                            `type="uinteger" default="1"' minmax(1, 1))

                        def(`
A bit field that describes which Elements have been modified in this way. Values
(big-endian) can be OR'ed.
                        ')
                        <restriction>
                            enuments(1, `Block')
                                def(`
All frame contents, excluding lacing data.
                                ')
                            eenuments(2, `Private')
                                def(`
The tracks private data.
                                ')
                            eenuments(4, `Next')
                                def(`
The next ContentEncoding (next "ContentEncodingOrder". Either the data inside
"ContentCompression" and/or "ContentEncryption").
                                ')
                                usage(`
This value **SHOULD NOT** be used.
                                ')
                            enumente()
                        </restriction>
                        <extension type="webmproject.org" webm="1"/>
                        <extension type="stream copy" keep="1"/>

                    <!-- \Segment\Tracks\TrackEntry\ContentEncodings
                         \ContentEncoding\ContentEncodingType -->
                    enextes(`ContentEncodingType', `0x5033',
                            `type="uinteger" default="0"' minmax(1, 1))

                        def(`
A value describing what kind of transformation is applied.
                        ')
                        <restriction>
                            enument(0, `Compression')
                            enument(1, `Encryption')
                        </restriction>
                        <extension type="webmproject.org" webm="1"/>
                        <extension type="stream copy" keep="1"/>

                    <!-- \Segment\Tracks\TrackEntry\ContentEncodings
                         \ContentEncoding\ContentCompression -->
                    enextes(`ContentCompression', `0x5034',
                            `type="master" maxOccurs="1"')

                        def(`
Settings describing the compression used. This Element **MUST** be present if
the value of ContentEncodingType is 0 and absent otherwise. Each block **MUST**
be decompressable even if no previous block is available in order not to prevent
seeking.
                        ')
                        <extension type="stream copy" keep="1"/>

                        <!-- \Segment\Tracks\TrackEntry\ContentEncodings
                             \ContentEncoding\ContentCompression
                             \ContentCompAlgo -->
                        epushes(`ContentCompAlgo', `0x4254',
                                `type="uinteger" default="0"' minmax(1, 1))

                            def(`
The compression algorithm used.
                            ')
                            <restriction>
                                enuments(0, `zlib')
                                    def(`
zlib compression [@!RFC1950].
                                    ')
                                eenuments(1, `bzlib')
                                    def(`
bzip2 compression [@!BZIP2], **SHOULD NOT** be used; see usage notes.
                                    ')
                                eenuments(2, `lzo1x')
                                    def(`
Lempel-Ziv-Oberhumer compression [@!LZO], **SHOULD NOT** be used; see usage
notes.
                                    ')
                                eenuments(3, `Header Stripping')
                                    def(`
Octets in "ContentCompSettings" ((#contentcompsettings-element)) have been
stripped from each frame.
                                    ')
                                enumente()
                            </restriction>
                            usage(`
Compression method "1" (bzlib) and "2" (lzo1x) are lacking proper documentation
on the format which limits implementation possibilities. Due to licensing
conflicts on commonly available libraries compression methods "2" (lzo1x) does
not offer widespread interoperability. Decoding implementations **MAY** support
methods "1" and "2" as possible. The use of these compression methods **SHOULD
NOT** be used as a default.
                            ')
                            <extension type="stream copy" keep="1"/>

                        <!-- \Segment\Tracks\TrackEntry\ContentEncodings
                             \ContentEncoding\ContentCompression
                             \ContentCompSettings -->
                        enextes(`ContentCompSettings', `0x4255',
                                `type="binary" maxOccurs="1"')

                            def(`
Settings that might be needed by the decompressor. For Header Stripping
("ContentCompAlgo"=3), the bytes that were removed from the beginning of each
frames of the track.
                            ')
                            <extension type="stream copy" keep="1"/>

                        epop()

                    ppop()

                    <!-- \Segment\Tracks\TrackEntry\ContentEncodings
                         \ContentEncoding\ContentEncryption -->
                    pushes(`ContentEncryption', `0x5035',
                           `type="master" maxOccurs="1"')

                        def(`
Settings describing the encryption used. This Element **MUST** be present if the
value of "ContentEncodingType" is 1 (encryption) and **MUST** be ignored
otherwise.
                        ')
                        <extension type="webmproject.org" webm="1"/>
                        <extension type="stream copy" keep="1"/>

                        <!-- \Segment\Tracks\TrackEntry\ContentEncodings
                             \ContentEncoding\ContentEncryption
                             \ContentEncAlgo -->
                        epushes(`ContentEncAlgo', `0x47E1',
                                `type="uinteger" default="0"' minmax(1, 1))

                            def(`
The encryption algorithm used. The value "0" means that the contents have not
been encrypted.
                            ')
                            <restriction>
                                enument(0, `Not encrypted')
                                enuments(1, `DES')
                                    def(`
Data Encryption Standard (DES) [@!FIPS.46-3].
                                    ')
                                eenuments(2, `3DES')
                                    def(`
Triple Data Encryption Algorithm [@!SP.800-67].
                                    ')
                                eenuments(3, `Twofish')
                                    def(`
Twofish Encryption Algorithm [@!Twofish].
                                    ')
                                eenuments(4, `Blowfish')
                                    def(`
Blowfish Encryption Algorithm [@!Blowfish].
                                    ')
                                eenuments(5, `AES')
                                    def(`
Advanced Encryption Standard (AES) [@!FIPS.197].
                                    ')
                                enumente()
                            </restriction>
                            <extension type="webmproject.org" webm="1"/>
                            <extension type="stream copy" keep="1"/>

                        <!-- \Segment\Tracks\TrackEntry\ContentEncodings
                             \ContentEncoding\ContentEncryption
                             \ContentEncKeyID -->
                        enextes(`ContentEncKeyID', `0x47E2',
                                `type="binary" maxOccurs="1"')

                            def(`
For public key algorithms this is the ID of the public key the the data was
encrypted with.
                            ')
                            <extension type="webmproject.org" webm="1"/>
                            <extension type="stream copy" keep="1"/>

                        <!-- \Segment\Tracks\TrackEntry\ContentEncodings
                             \ContentEncoding\ContentEncryption
                             \ContentEncAESSettings -->
                        enextes(`ContentEncAESSettings', `0x47E7',
                                `type="master" minver="4" maxOccurs="1"')

                            def(`
Settings describing the encryption algorithm used. It **MUST** be ignored if
"ContentEncAlgo" is not AES (5).
                            ')
                            <extension type="webmproject.org" webm="1"/>
                            <extension type="stream copy" keep="1"/>

                            <!-- \Segment\Tracks\TrackEntry\ContentEncodings
                                 \ContentEncoding\ContentEncryption
                                 \ContentEncAESSettings
                                 \AESSettingsCipherMode -->
                            epushes(`AESSettingsCipherMode', `0x47E8',
                                    `type="uinteger" minver="4"' minmax(1, 1))

                                def(`
The AES cipher mode used in the encryption. It **MUST** be ignored if
"ContentEncAlgo" is not AES (5).
                                ')
                                <restriction>
                                    enuments(1, `AES-CTR')
                                        def(`
Counter [@!SP.800-38A].
                                        ')
                                    eenuments(2, `AES-CBC')
                                        def(`
Cipher Block Chaining [@!SP.800-38A].
                                        ')
                                    enumente()
                                </restriction>
                                <extension type="webmproject.org" webm="1"/>
                                <extension type="stream copy" keep="1"/>

                            epop()

                        ppop()

                        <!-- \Segment\Tracks\TrackEntry\ContentEncodings
                             \ContentEncoding\ContentEncryption
                             \ContentSignature -->
                        pushes(`ContentSignature', `0x47E3',
                               `type="binary" maxver="0" maxOccurs="1"')

                            def(`
A cryptographic signature of the contents.
                            ')

                        <!-- \Segment\Tracks\TrackEntry\ContentEncodings
                             \ContentEncoding\ContentEncryption
                             \ContentSigKeyID -->
                        enextes(`ContentSigKeyID', `0x47E4',
                                `type="binary" maxver="0" maxOccurs="1"')

                            def(`
This is the ID of the private key the data was signed with.
                            ')

                        <!-- \Segment\Tracks\TrackEntry\ContentEncodings
                             \ContentEncoding\ContentEncryption
                             \ContentSigAlgo -->
                        enextes(`ContentSigAlgo', `0x47E5',
                                `type="uinteger" maxver="0" default="0" maxOccurs="1"')

                            def(`
The algorithm used for the signature.
                            ')
                            <restriction>
                                enument(0, `Not signed')
                                enument(1, `RSA')
                            </restriction>

                        <!-- \Segment\Tracks\TrackEntry\ContentEncodings
                             \ContentEncoding\ContentEncryption
                             \ContentSigHashAlgo -->
                        enextes(`ContentSigHashAlgo', `0x47E6',
                                `type="uinteger" maxver="0" default="0" maxOccurs="1"')

                            def(`
The hash algorithm used for the signature.
                            ')
                            <restriction>
                                enument(0, `Not signed')
                                enument(1, `SHA1-160')
                                enument(2, `MD5')
                            </restriction>

                        epop()

                    ppop()

                ppop()

            ppop()

        ppop()

    ppop()

    <!-- \Segment\Cues -->
    pushes(`Cues', `0x1C53BB6B',
           `type="master" maxOccurs="1"')

        def(`
A Top-Level Element to speed seeking access. All entries are local to the
Segment.
        ')
        <implementation_note note_attribute="minOccurs">
This Element **SHOULD** be set when the Segment is not transmitted as a live
stream (see #livestreaming).
        </implementation_note>
        <extension type="webmproject.org" webm="1"/>

        <!-- \Segment\Cues\CuePoint -->
        epushes(`CuePoint', `0xBB',
                type="master" minOccurs="1"')

            def(`
Contains all information relative to a seek point in the Segment.
            ')
            <extension type="webmproject.org" webm="1"/>

            <!-- \Segment\Cues\CuePoint\CueTime -->
            epushes(`CueTime', `0xB3',
                    `type="uinteger"' minmax(1, 1))

                def(`
Absolute timestamp of the seek point, expressed in Matroska Ticks -- ie in
nanoseconds; see (#timestamp-ticks).
                ')
                <extension type="webmproject.org" webm="1"/>

            <!-- \Segment\Cues\CuePoint\CueTrackPositions -->
            enextes(`CueTrackPositions', `0xB7',
                    `type="master" minOccurs="1"')

                def(`
Contain positions for different tracks corresponding to the timestamp.
                ')
                <extension type="webmproject.org" webm="1"/>

                <!-- \Segment\Cues\CuePoint\CueTrackPositions\CueTrack -->
                epushes(`CueTrack', `0xF7',
                        `type="uinteger" range="not 0"' minmax(1, 1))

                    def(`
The track for which a position is given.
                    ')
                    <extension type="webmproject.org" webm="1"/>

                <!-- \Segment\Cues\CuePoint\CueTrackPositions
                     \CueClusterPosition -->
                enextes(`CueClusterPosition', `0xF1',
                        `type="uinteger"' minmax(1, 1))

                    def(`
The Segment Position of the Cluster containing the associated Block.
                    ')
                    <extension type="webmproject.org" webm="1"/>

                <!-- \Segment\Cues\CuePoint\CueTrackPositions
                     \CueRelativePosition -->
                enextes(`CueRelativePosition', `0xF0',
                        `type="uinteger" minver="4" maxOccurs="1"')

                    def(`
The relative position inside the Cluster of the referenced SimpleBlock or
BlockGroup with 0 being the first possible position for an Element inside that
Cluster.
                    ')
                    <extension type="webmproject.org" webm="1"/>

                <!-- \Segment\Cues\CuePoint\CueTrackPositions\CueDuration -->
                enextes(`CueDuration', `0xB2',
                        `type="uinteger" minver="4" maxOccurs="1"')

                    def(`
The duration of the block, expressed in Segment Ticks which is based on
TimestampScale; see (#timestamp-ticks). If missing, the tracks DefaultDuration
does not apply and no duration information is available in terms of the cues.
                    ')
                    <extension type="webmproject.org" webm="1"/>

                <!-- \Segment\Cues\CuePoint\CueTrackPositions\CueBlockNumber -->
                enextes(`CueBlockNumber', `0x5378',
                        `type="uinteger" range="not 0" maxOccurs="1"')

                    def(`
Number of the Block in the specified Cluster.
                    ')
                    <extension type="webmproject.org" webm="1"/>

                <!-- \Segment\Cues\CuePoint\CueTrackPositions\CueCodecState -->
                enextes(`CueCodecState', `0xEA',
                        `type="uinteger" minver="2" default="0"' minmax(1, 1))

                    def(`
The Segment Position of the Codec State corresponding to this Cue Element. 0
means that the data is taken from the initial Track Entry.
                    ')

                <!-- \Segment\Cues\CuePoint\CueTrackPositions\CueReference -->
                enextes(`CueReference', `0xDB',
                        `type="master" minver="2"')

                    def(`
The Clusters containing the referenced Blocks.
                    ')

                    <!-- \Segment\Cues\CuePoint\CueTrackPositions\CueReference
                         \CueRefTime -->
                    epushes(`CueRefTime', `0x96',
                            `type="uinteger" minver="2"' minmax(1, 1))

                        def(`
Timestamp of the referenced Block, expressed in Matroska Ticks -- ie in
nanoseconds; see (#timestamp-ticks).
                        ')

                    <!-- \Segment\Cues\CuePoint\CueTrackPositions\CueReference
                         \CueRefCluster -->
                    enextes(`CueRefCluster', `0x97',
                            `type="uinteger"' minmaxver(0, 0) minmax(1, 1))

                        def(`
The Segment Position of the Cluster containing the referenced Block.
                        ')

                    <!-- \Segment\Cues\CuePoint\CueTrackPositions\CueReference
                         \CueRefNumber -->
                    enextes(`CueRefNumber', `0x535F',
                            `type="uinteger" range="not 0"' minmaxver(0, 0)
                            `default="1" maxOccurs="1"')

                        def(`
Number of the referenced Block of Track X in the specified Cluster.
                        ')

                    <!-- \Segment\Cues\CuePoint\CueTrackPositions\CueReference
                         \CueRefCodecState -->
                    enextes(`CueRefCodecState', `0xEB',
                            `type="uinteger"' minmaxver(0, 0)
                            `default="0" maxOccurs="1"')

                        def(`
The Segment Position of the Codec State corresponding to this referenced
Element. 0 means that the data is taken from the initial Track Entry.
                        ')

                    epop()

                ppop()

            ppop()

        ppop()

    ppop()

    <!-- \Segment\Attachments -->
    pushes(`Attachments', `0x1941A469',
           `type="master" maxOccurs="1"')

        def(`
Contain attached files.
        ')

        <!-- \Segment\Attachments\AttachedFile -->
        epushes(`AttachedFile', `0x61A7',
                `type="master" minOccurs="1"')

            def(`
An attached file.
            ')
            <extension type="libmatroska" cppname="Attached"/>

            <!-- \Segment\Attachments\AttachedFile\FileDescription -->
            epushes(`FileDescription', `0x467E',
                    `type="utf-8" maxOccurs="1"')

                def(`
A human-friendly name for the attached file.
                ')

            <!-- \Segment\Attachments\AttachedFile\FileName -->
            enextes(`FileName', `0x466E',
                    `type="utf-8"' minmax(1, 1))

                def(`
Filename of the attached file.
                ')

            <!-- \Segment\Attachments\AttachedFile\FileMimeType -->
            enextes(`FileMimeType', `0x4660',
                    `type="string"' minmax(1, 1))

                def(`
MIME type of the file.
                ')
                <extension type="libmatroska" cppname="MimeType"/>
                <extension type="stream copy" keep="1"/>

            <!-- \Segment\Attachments\AttachedFile\FileData -->
            enextes(`FileData', `0x465C',
                    `type="binary"' minmax(1, 1))

                def(`
The data of the file.
                ')
                <extension type="stream copy" keep="1"/>

            <!-- \Segment\Attachments\AttachedFile\FileUID -->
            enextes(`FileUID', `0x46AE',
                    `type="uinteger" range="not 0"' minmax(1, 1))

                def(`
Unique ID representing the file, as random as possible.
                ')
                <extension type="stream copy" keep="1"/>

            <!-- \Segment\Attachments\AttachedFile\FileReferral -->
            enextes(`FileReferral', `0x4675',
                    `type="binary"' minmaxver(0, 0) `maxOccurs="1"')

                def(`
A binary value that a track/codec can refer to when the attachment is needed.
                ')

            <!-- \Segment\Attachments\AttachedFile\FileUsedStartTime -->
            enextes(`FileUsedStartTime', `0x4661',
                    `type="uinteger"' minmaxver(0, 0) `maxOccurs="1"')

                def(`
The timestamp at which this optimized font attachment comes into context,
expressed in Segment Ticks which is based on TimestampScale. See
[@?DivXWorldFonts].
                ')
                usage(`
This element is reserved for future use and if written **MUST** be the segment
start timestamp.
                ')
                <extension type="divx.com" divx="1"/>

            <!-- \Segment\Attachments\AttachedFile\FileUsedEndTime -->
            enextes(`FileUsedEndTime', `0x4662',
                    `type="uinteger"' minmaxver(0, 0) `maxOccurs="1"')

                def(`
The timestamp at which this optimized font attachment goes out of context,
expressed in Segment Ticks which is based on TimestampScale. See
[@?DivXWorldFonts].
                ')
                usage(`
This element is reserved for future use and if written **MUST** be the segment
end timestamp.
                ')
                <extension type="divx.com" divx="1"/>

            epop()

        ppop()

    ppop()

    <!-- \Segment\Chapters -->
    pushes(`Chapters', `0x1043A770',
           `type="master" maxOccurs="1" recurring="1"')

        def(`
A system to define basic menus and partition data. For more detailed
information, look at the Chapters explanation in (#chapters).
        ')
        <extension type="webmproject.org" webm="1"/>

        <!-- \Segment\Chapters\EditionEntry -->
        epushes(`EditionEntry', `0x45B9',
                `type="master" minOccurs="1"')

            def(`
Contains all information about a Segment edition.
            ')
            <extension type="webmproject.org" webm="1"/>

            <!-- \Segment\Chapters\EditionEntry\EditionUID -->
            epushes(`EditionUID', `0x45BC',
                    `type="uinteger" range="not 0" maxOccurs="1"')

                def(`
A unique ID to identify the edition. Its useful for tagging an edition.
                ')
                <extension type="stream copy" keep="1"/>

            <!-- \Segment\Chapters\EditionEntry\EditionFlagHidden -->
            enextes(`EditionFlagHidden', `0x45BD',
                    `type="uinteger" range="0-1" default="0"' minmax(1, 1))

                def(`
Set to 1 if an edition is hidden. Hidden editions **SHOULD NOT** be available to
the user interface (but still to Control Tracks; see (#chapter-flags) on Chapter
flags).
                ')
                <extension type="other document" spec="control-track"/>

            <!-- \Segment\Chapters\EditionEntry\EditionFlagDefault -->
            enextes(`EditionFlagDefault', `0x45DB',
                    `type="uinteger" range="0-1" default="0"' minmax(1, 1))

                def(`
Set to 1 if the edition **SHOULD** be used as the default one.
                ')

            <!-- \Segment\Chapters\EditionEntry\EditionFlagOrdered -->
            enextes(`EditionFlagOrdered', `0x45DD',
                    `type="uinteger" range="0-1" default="0"' minmax(1, 1))

                def(`
Set to 1 if the chapters can be defined multiple times and the order to play
them is enforced; see (#editionflagordered).
                ')

            <!-- \Segment\Chapters\EditionEntry\+ChapterAtom -->
            enextes(`+ChapterAtom', `0xB6',
                    `type="master" minOccurs="1" recursive="1"')

                def(`
Contains the atom information to use as the chapter atom (apply to all tracks).
                ')
                <extension type="webmproject.org" webm="1"/>

                <!-- \Segment\Chapters\EditionEntry\+ChapterAtom\ChapterUID -->
                epushes(`ChapterUID', `0x73C4',
                        `type="uinteger" range="not 0"' minmax(1, 1))

                    def(`
A unique ID to identify the Chapter.
                    ')
                    <extension type="webmproject.org" webm="1"/>
                    <extension type="stream copy" keep="1"/>

                <!-- \Segment\Chapters\EditionEntry\+ChapterAtom
                     \ChapterStringUID -->
                enextes(`ChapterStringUID', `0x5654',
                        `type="utf-8" minver="3" maxOccurs="1"')

                    def(`
A unique string ID to identify the Chapter. Use for WebVTT cue identifier
storage [@!WebVTT].
                    ')
                    <extension type="webmproject.org" webm="1"/>

                <!-- \Segment\Chapters\EditionEntry\+ChapterAtom
                     \ChapterTimeStart -->
                enextes(`ChapterTimeStart', `0x91',
                        `type="uinteger"' minmax(1, 1))

                    def(`
Timestamp of the start of Chapter, expressed in Matroska Ticks -- ie in
nanoseconds; see (#timestamp-ticks).
                    ')
                    <extension type="webmproject.org" webm="1"/>

                <!-- \Segment\Chapters\EditionEntry\+ChapterAtom
                     \ChapterTimeEnd -->
                enextes(`ChapterTimeEnd', `0x92',
                        `type="uinteger" maxOccurs="1"')

                    def(`
Timestamp of the end of Chapter timestamp excluded, expressed in Matroska Ticks
-- ie in nanoseconds; see (#timestamp-ticks). The value **MUST** be greater than
or equal to the "ChapterTimeStart" of the same "ChapterAtom".
                    ')
                    usage(`
The "ChapterTimeEnd" timestamp value being excluded, it **MUST** take in account
the duration of the last frame it includes, especially for the "ChapterAtom"
using the last frames of the "Segment".
                    ')
                    <implementation_note note_attribute="minOccurs">
ChapterTimeEnd **MUST** be set (minOccurs=1) if the Edition is an ordered
edition; see (#editionflagordered), unless its a "Parent Chapter"; see
(#nested-chapters)
                    </implementation_note>
                    <extension type="webmproject.org" webm="1"/>

                <!-- \Segment\Chapters\EditionEntry\+ChapterAtom
                     \ChapterFlagHidden -->
                enextes(`ChapterFlagHidden', `0x98',
                        `type="uinteger" range="0-1" default="0"' minmax(1, 1))

                    def(`
Set to 1 if a chapter is hidden. Hidden chapters **SHOULD NOT** be available to
the user interface (but still to Control Tracks; see (#chapterflaghidden) on
Chapter flags).
                    ')

                <!-- \Segment\Chapters\EditionEntry\+ChapterAtom
                     \ChapterFlagEnabled -->
                enextes(`ChapterFlagEnabled', `0x4598',
                        `type="uinteger" range="0-1" default="1"' minmax(1, 1))

                    def(`
Set to 1 if the chapter is enabled. It can be enabled/disabled by a Control
Track. When disabled, the movie **SHOULD** skip all the content between the
TimeStart and TimeEnd of this chapter; see (#chapter-flags) on Chapter flags.
                    ')
                    <extension type="other document" spec="control-track"/>

                <!-- \Segment\Chapters\EditionEntry\+ChapterAtom
                     \ChapterSegmentUID -->
                enextes(`ChapterSegmentUID', `0x6E67',
                        `type="binary" range="&gt;0" length="16" maxOccurs="1"')

                    def(`
The SegmentUID of another Segment to play during this chapter.
                    ')
                    usage(`
The value **MUST NOT** be the "SegmentUID" value of the "Segment" it belongs to.
                    ')
                    <implementation_note note_attribute="minOccurs">
ChapterSegmentUID **MUST** be set (minOccurs=1) if ChapterSegmentEditionUID is
used; see (#medium-linking) on medium-linking Segments.
                    </implementation_note>

                <!-- \Segment\Chapters\EditionEntry\+ChapterAtom
                     \ChapterSegmentEditionUID -->
                enextes(`ChapterSegmentEditionUID', `0x6EBC',
                        `type="uinteger" range="not 0" maxOccurs="1"')

                    def(`
The EditionUID to play from the Segment linked in ChapterSegmentUID. If
ChapterSegmentEditionUID is undeclared, then no Edition of the linked Segment is
used; see (#medium-linking) on medium-linking Segments.
                    ')

                <!-- \Segment\Chapters\EditionEntry\+ChapterAtom
                     \ChapterPhysicalEquiv -->
                enextes(`ChapterPhysicalEquiv', `0x63C3',
                        `type="uinteger" maxOccurs="1"')

                    def(`
Specify the physical equivalent of this ChapterAtom like "DVD" (60) or "SIDE"
(50); see (#physical-types) for a complete list of values.
                    ')

                <!-- \Segment\Chapters\EditionEntry\+ChapterAtom
                     \ChapterTrack -->
                enextes(`ChapterTrack', `0x8F',
                        `type="master" maxOccurs="1"')

                    def(`
List of tracks on which the chapter applies. If this Element is not present, all
tracks apply
                    ')
                    <extension type="other document" spec="control-track"/>

                    <!-- \Segment\Chapters\EditionEntry\+ChapterAtom
                         \ChapterTrack\ChapterTrackUID -->
                    epushes(`ChapterTrackUID', `0x89',
                            `type="uinteger" range="not 0" minOccurs="1"')

                        def(`
UID of the Track to apply this chapter to. In the absence of a control track,
choosing this chapter will select the listed Tracks and deselect unlisted
tracks. Absence of this Element indicates that the Chapter **SHOULD** be applied
to any currently used Tracks.
                        ')
                        <extension type="libmatroska"
                            cppname="ChapterTrackNumber"/>
                        <extension type="other document" spec="control-track"/>

                    epop()

                ppop()

                <!-- \Segment\Chapters\EditionEntry\+ChapterAtom
                     \ChapterDisplay -->
                pushes(`ChapterDisplay', `0x80',
                       `type="master"')

                    def(`
Contains all possible strings to use for the chapter display.
                    ')
                    <extension type="webmproject.org" webm="1"/>

                    <!-- \Segment\Chapters\EditionEntry\+ChapterAtom
                         \ChapterDisplay\ChapString -->
                    epushes(`ChapString', `0x85',
                            `type="utf-8"' minmax(1, 1))

                        def(`
Contains the string to use as the chapter atom.
                        ')
                        <extension type="webmproject.org" webm="1"/>
                        <extension type="libmatroska" cppname="ChapterString"/>

                    <!-- \Segment\Chapters\EditionEntry\+ChapterAtom
                         \ChapterDisplay\ChapLanguage -->
                    enextes(`ChapLanguage', `0x437C',
                            `type="string" default="eng" minOccurs="1"')

                        def(`
A language corresponding to the string, in the bibliographic ISO-639-2 form
[@!ISO639-2]. This Element **MUST** be ignored if a ChapLanguageIETF Element is
used within the same ChapterDisplay Element.
                        ')
                        <extension type="webmproject.org" webm="1"/>
                        <extension type="libmatroska"
                            cppname="ChapterLanguage"/>

                    <!-- \Segment\Chapters\EditionEntry\+ChapterAtom
                         \ChapterDisplay\ChapLanguageIETF -->
                    enextes(`ChapLanguageIETF', `0x437D',
                            `type="string" minver="4"')

                        def(`
Specifies a language corresponding to the ChapString in the format defined in
[@!BCP47] and using the IANA Language Subtag Registry [@!IANALangRegistry]. If a
ChapLanguageIETF Element is used, then any ChapLanguage and ChapCountry Elements
used in the same ChapterDisplay **MUST** be ignored.
                        ')

                    <!-- \Segment\Chapters\EditionEntry\+ChapterAtom
                         \ChapterDisplay\ChapCountry -->
                    enextes(`ChapCountry', `0x437E',
                            `type="string"')

                        def(`
A country corresponding to the string, using the same 2 octets country-codes as
in Internet domains [@!IANADomains] based on [@!ISO3166-1] alpha-2 codes. This
Element **MUST** be ignored if a ChapLanguageIETF Element is used within the
same ChapterDisplay Element.
                        ')
                        <extension type="webmproject.org" webm="1"/>
                        <extension type="libmatroska" cppname="ChapterCountry"/>

                    epop()

                ppop()

                <!-- \Segment\Chapters\EditionEntry\+ChapterAtom\ChapProcess -->
                pushes(`ChapProcess', `0x6944',
                       `type="master"')

                    def(`
Contains all the commands associated to the Atom.
                    ')
                    <extension type="libmatroska" cppname="ChapterProcess"/>

                    <!-- \Segment\Chapters\EditionEntry\+ChapterAtom\ChapProcess
                         \ChapProcessCodecID -->
                    epushes(`ChapProcessCodecID', `0x6955',
                            `type="uinteger" default="0"' minmax(1, 1))

                        def(`
Contains the type of the codec used for the processing. A value of 0 means
native Matroska processing (to be defined), a value of 1 means the DVD command
set is used; see (#menu-features) on DVD menus. More codec IDs can be added
later.
                        ')
                        <extension type="libmatroska"
                            cppname="ChapterProcessCodecID"/>

                    <!-- \Segment\Chapters\EditionEntry\+ChapterAtom\ChapProcess
                         \ChapProcessPrivate -->
                    enextes(`ChapProcessPrivate', `0x450D',
                            `type="binary" maxOccurs="1"')

                        def(`
Some optional data attached to the ChapProcessCodecID information. For
ChapProcessCodecID = 1, it is the "DVD level" equivalent; see (#menu-features)
on DVD menus.
                        ')
                        <extension type="libmatroska"
                            cppname="ChapterProcessPrivate"/>

                    <!-- \Segment\Chapters\EditionEntry\+ChapterAtom\ChapProcess
                         \ChapProcessCommand -->
                    enextes(`ChapProcessCommand', `0x6911',
                            `type="master"')

                        def(`
Contains all the commands associated to the Atom.
                        ')
                        <extension type="libmatroska"
                            cppname="ChapterProcessCommand"/>

                        <!-- \Segment\Chapters\EditionEntry\+ChapterAtom
                             \ChapProcess\ChapProcessCommand\ChapProcessTime -->
                        epushes(`ChapProcessTime', `0x6922',
                                `type="uinteger"' minmax(1, 1))

                            def(`
Defines when the process command **SHOULD** be handled
                            ')
                            <restriction>
                                enument(0, `during the whole chapter')
                                enument(1, `before starting playback')
                                enument(2, `after playback of the chapter')
                            </restriction>
                            <extension type="libmatroska"
                                cppname="ChapterProcessTime"/>

                        <!-- \Segment\Chapters\EditionEntry\+ChapterAtom
                             \ChapProcess\ChapProcessCommand\ChapProcessData -->
                        enextes(`ChapProcessData', `0x6933',
                                `type="binary"' minmax(1, 1))

                            def(`
Contains the command information. The data **SHOULD** be interpreted depending
on the ChapProcessCodecID value. For ChapProcessCodecID = 1, the data correspond
to the binary DVD cell pre/post commands; see (#menu-features) on DVD menus.
                            ')
                            <extension type="libmatroska"
                                cppname="ChapterProcessData"/>

                        epop()

                    ppop()

                ppop()

            ppop()

        ppop()

    ppop()

    <!-- \Segment\Tags -->
    pushes(`Tags', `0x1254C367',
           `type="master"')

        def(`
Element containing metadata describing Tracks, Editions, Chapters, Attachments,
or the Segment as a whole. A list of valid tags can be found in
[@!MatroskaTags].
        ')
        <extension type="webmproject.org" webm="1"/>

        <!-- \Segment\Tags\Tag -->
        epushes(`Tag', `0x7373',
                `type="master" minOccurs="1"')

            def(`
A single metadata descriptor.
            ')
            <extension type="webmproject.org" webm="1"/>

            <!-- \Segment\Tags\Tag\Targets -->
            epushes(`Targets', `0x63C0',
                    `type="master"' minmax(1, 1))

                def(`
Specifies which other elements the metadata represented by the Tag applies to.
If empty or not present, then the Tag describes everything in the Segment.
                ')
                <extension type="webmproject.org" webm="1"/>
                <extension type="libmatroska" cppname="TagTargets"/>

                <!-- \Segment\Tags\Tag\Targets\TargetTypeValue -->
                epushes(`TargetTypeValue', `0x68CA',
                        `type="uinteger" default="50"' minmax(1, 1))

                    def(`
A number to indicate the logical level of the target.
                    ')
                    <restriction>
                        enuments(70, `COLLECTION')
                            def(`
The highest hierarchical level that tags can describe.
                            ')
                        eenuments(60,
                                  `EDITION / ISSUE / VOLUME / OPUS / SEASON / SEQUEL')
                            def(`
A list of lower levels grouped together.
                            ')
                        eenuments(50,
                                  `ALBUM / OPERA / CONCERT / MOVIE / EPISODE')
                            def(`
The most common grouping level of music and video (equals to an episode for TV
series).
                            ')
                        eenuments(40, `PART / SESSION')
                            def(`
When an album or episode has different logical parts.
                            ')
                        eenuments(30, `TRACK / SONG / CHAPTER')
                            def(`
The common parts of an album or movie.
                            ')
                        eenuments(20, `SUBTRACK / PART / MOVEMENT / SCENE')
                            def(`
Corresponds to parts of a track for audio (like a movement).
                            ')
                        eenuments(10, `SHOT')
                            def(`
The lowest hierarchy found in music or movies.
                            ')
                        enumente()
                    </restriction>
                    <extension type="webmproject.org" webm="1"/>
                    <extension type="libmatroska" cppname="TagTargetTypeValue"/>

                <!-- \Segment\Tags\Tag\Targets\TargetType -->
                enextes(`TargetType', `0x63CA',
                        `type="string" maxOccurs="1"')

                    def(`
An informational string that can be used to display the logical level of the
target like "ALBUM", "TRACK", "MOVIE", "CHAPTER", etc; see Section 6.4 of
[@!MatroskaTags].
                    ')
                    <restriction>
                        enument(`COLLECTION', `COLLECTION')
                        enument(`EDITION', `EDITION')
                        enument(`ISSUE', `ISSUE')
                        enument(`VOLUME', `VOLUME')
                        enument(`OPUS', `OPUS')
                        enument(`SEASON', `SEASON')
                        enument(`SEQUEL', `SEQUEL')
                        enument(`ALBUM', `ALBUM')
                        enument(`OPERA', `OPERA')
                        enument(`CONCERT', `CONCERT')
                        enument(`MOVIE', `MOVIE')
                        enument(`EPISODE', `EPISODE')
                        enument(`PART', `PART')
                        enument(`SESSION', `SESSION')
                        enument(`TRACK', `TRACK')
                        enument(`SONG', `SONG')
                        enument(`CHAPTER', `CHAPTER')
                        enument(`SUBTRACK', `SUBTRACK')
                        enument(`PART', `PART')
                        enument(`MOVEMENT', `MOVEMENT')
                        enument(`SCENE', `SCENE')
                        enument(`SHOT', `SHOT')
                    </restriction>
                    <extension type="webmproject.org" webm="1"/>
                    <extension type="libmatroska" cppname="TagTargetType"/>

                <!-- \Segment\Tags\Tag\Targets\TagTrackUID -->
                enextes(`TagTrackUID', `0x63C5',
                        `type="uinteger" default="0"')

                    def(`
A unique ID to identify the Track(s) the tags belong to.
                    ')
                    usage(`
If the value is 0 at this level, the tags apply to all tracks in the Segment. If
set to any other value, it **MUST** match the "TrackUID" value of a track found
in this Segment.
                    ')
                    <extension type="webmproject.org" webm="1"/>

                <!-- \Segment\Tags\Tag\Targets\TagEditionUID -->
                enextes(`TagEditionUID', `0x63C9',
                        `type="uinteger" default="0"')

                    def(`
A unique ID to identify the EditionEntry(s) the tags belong to.
                    ')
                    usage(`
If the value is 0 at this level, the tags apply to all editions in the Segment.
If set to any other value, it **MUST** match the "EditionUID" value of an
edition found in this Segment.
                    ')

                <!-- \Segment\Tags\Tag\Targets\TagChapterUID -->
                enextes(`TagChapterUID', `0x63C4',
                        `type="uinteger" default="0"')

                    def(`
A unique ID to identify the Chapter(s) the tags belong to.
                    ')
                    usage(`
If the value is 0 at this level, the tags apply to all chapters in the Segment.
If set to any other value, it **MUST** match the "ChapterUID" value of a chapter
found in this Segment.
                    ')

                <!-- \Segment\Tags\Tag\Targets\TagAttachmentUID -->
                enextes(`TagAttachmentUID', `0x63C6',
                        `type="uinteger" default="0"')

                    def(`
A unique ID to identify the Attachment(s) the tags belong to.
                    ')
                    usage(`
If the value is 0 at this level, the tags apply to all the attachments in the
Segment. If set to any other value, it **MUST** match the "FileUID" value of an
attachment found in this Segment.
                    ')

                epop()

            ppop()

            <!-- \Segment\Tags\Tag\+SimpleTag -->
            pushes(`+SimpleTag', `0x67C8',
                   `type="master" minOccurs="1" recursive="1"')

                def(`
Contains general information about the target.
                ')
                <extension type="webmproject.org" webm="1"/>
                <extension type="libmatroska" cppname="TagSimple"/>

                <!-- \Segment\Tags\Tag\+SimpleTag\TagName -->
                epushes(`TagName', `0x45A3',
                        `type="utf-8"' minmax(1, 1))

                    def(`
The name of the Tag that is going to be stored.
                    ')
                    <extension type="webmproject.org" webm="1"/>

                <!-- \Segment\Tags\Tag\+SimpleTag\TagLanguage -->
                enextes(`TagLanguage', `0x447A',
                        `type="string" default="und"' minmax(1, 1))

                    def(`
Specifies the language of the tag specified, in the Matroska languages form; see
(#language-codes) on language codes. This Element **MUST** be ignored if the
TagLanguageIETF Element is used within the same SimpleTag Element.
                    ')
                    <extension type="webmproject.org" webm="1"/>
                    <extension type="libmatroska" cppname="TagLangue"/>

                <!-- \Segment\Tags\Tag\+SimpleTag\TagLanguageIETF -->
                enextes(`TagLanguageIETF', `0x447B',
                        `type="string" minver="4" maxOccurs="1"')

                    def(`
Specifies the language used in the TagString according to [@!BCP47] and using
the IANA Language Subtag Registry [@!IANALangRegistry]. If this Element is used,
then any TagLanguage Elements used in the same SimpleTag **MUST** be ignored.
                    ')

                <!-- \Segment\Tags\Tag\+SimpleTag\TagDefault -->
                enextes(`TagDefault', `0x4484',
                        `type="uinteger" range="0-1" default="1"' minmax(1, 1))

                    def(`
A boolean value to indicate if this is the default/original language to use for
the given tag.
                    ')
                    <extension type="webmproject.org" webm="1"/>

                <!-- \Segment\Tags\Tag\+SimpleTag\TagDefaultBogus -->
                enextes(`TagDefaultBogus', `0x44B4',
                        `type="uinteger" range="0-1"' minmaxver(0, 0)
                        `default="1"' minmax(1, 1))

                    def(`
A variant of the TagDefault element with a bogus Element ID; see
(#tagdefault-element).
                    ')

                <!-- \Segment\Tags\Tag\+SimpleTag\TagString -->
                enextes(`TagString', `0x4487',
                        `type="utf-8" maxOccurs="1"')

                    def(`
The value of the Tag.
                    ')
                    <extension type="webmproject.org" webm="1"/>

                <!-- \Segment\Tags\Tag\+SimpleTag\TagBinary -->
                enextes(`TagBinary', `0x4485',
                        `type="binary" maxOccurs="1"')

                    def(`
The values of the Tag, if it is binary. Note that this cannot be used in the
same SimpleTag as TagString.
                    ')
                    <extension type="webmproject.org" webm="1"/>

                epop()

            ppop()

        ppop()

    ppop()

ppop()

</EBMLSchema>

<!-- vi: set filetype=xml: -->
