dnl
dnl schema.m4
dnl

include(`schemas/schema_util.m4')

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

dnl vi: set expandtab sw=4 ts=4:
