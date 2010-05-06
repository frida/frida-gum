#! /usr/bin/env python
# encoding: utf-8

VERSION='0.1'
APPNAME='libgum'

srcdir = '.'
blddir = 'build'

def set_options(opt):
	pass

def configure(conf):
	conf.check_tool('gcc')
	if not conf.env['CC']: fatal('gcc not found')

	conf.check_tool('g++')
	if not conf.env['CXX']: fatal('g++ not found')

	conf.check_tool('gas')
	if not conf.env['AS']: conf.env['AS'] = conf.env['CC']

	conf.check_tool('gnome')

	conf.check_cfg(package='glib-2.0', uselib_store='GLIB', atleast_version='2.18.0', args='--cflags --libs', mandatory=True)
	conf.check_cfg(package='gobject-2.0', uselib_store='GOBJECT', atleast_version='2.18.0', args='--cflags --libs', mandatory=True)
	conf.check_cfg(package='gmodule-2.0', uselib_store='GMODULE', atleast_version='2.18.0', args='--cflags --libs', mandatory=True)
	conf.check_cfg(package='gthread-2.0', uselib_store='GTHREAD', atleast_version='2.18.0', args='--cflags --libs', mandatory=True)
	
	conf.check(header_name='udis86.h', mandatory=True)
	conf.check(lib='udis86', uselib='UDIS86', mandatory=True)

	conf.check(header_name='bfd.h', mandatory=True)
	conf.check(lib='bfd', uselib='BFD', mandatory=True)

	conf.define('VERSION', VERSION)
	conf.define('PACKAGE', 'libgum')

def build(bld):
	bld.add_subdirs('gum tests')

