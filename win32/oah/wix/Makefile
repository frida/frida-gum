###################
# MACROs
#

!IFNDEF version
!  ERROR version macro not specified
!ENDIF

!IFNDEF api_version
!  ERROR api version macro not specified
!ENDIF

!IFNDEF release_path
release_path=..\Win32\Release
!  MESSAGE release_path not defined, but set to $(release_path)
!ENDIF

module=gum

# output directories
output=.\Win32
IntDir=$(output)\obj
PDBDir=$(output)\pdb

# Tools
LIGHT=light.exe /nologo /o $(output)\$@ /pdbout $(PDBDir)\$*.wixpdb
TEMPLATE_TOOL="%OAH_INSTALLED_PATH%bin\wixt" "$?" $(release_path) $(module)

###################
# makefile targets
#
full: create_intdir dev

clean:
  -rd /Q /S $(output) 2>nul

create_intdir:
  @if NOT exist $(IntDir)\nul mkdir $(IntDir) >nul

#
# Redistributable Merge Modules containing binaries/shared [libraries/objects]
#
redist: $(module).msm

$(module).msm: $(IntDir)\$(module).wixobj
  $(LIGHT) $?

$(IntDir)\$(module).wxs: $(module).wxs.in; sed.exe -e "s/@VERSION@/$(version)/g" -e "s/@API_VERSION@/$(api_version)/g" "$?" > "$@"

#
# -dev package 
#
dev: redist $(module)-dev.msm $(module)-dev-installer.msi

$(module)-dev.msm: $(IntDir)\$(module)-dev.wixobj
  $(LIGHT) $?

$(module)-dev-installer.msi: $(IntDir)\$(module)-dev-installer.wixobj
  $(LIGHT) $?

$(IntDir)\$(module)-dev.wxs: $(IntDir)\$(module)-dev.wxs.template
  $(TEMPLATE_TOOL) > "$@"

$(IntDir)\$(module)-dev-installer.wxs: $(module)-dev-installer.wxs.in; sed.exe -e "s/@VERSION@/$(version)/g" -e "s/@API_VERSION@/$(api_version)/g" "$?" > "$@"
$(IntDir)\$(module)-dev.wxs.template: $(module)-dev.wxs.template.in; sed.exe -e "s/@VERSION@/$(version)/g" -e "s/@API_VERSION@/$(api_version)/g" "$?" > "$@"

###################
# makefile inference rules
#
.SUFFIXES: .wxs .wixobj

{$(IntDir)}.wxs{$(IntDir)}.wixobj::
  candle.exe /nologo /out $(IntDir)\ $<
