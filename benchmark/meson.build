# Copyright 2018 Google LLC
#
# Use of this source code is governed by an MIT-style
# license that can be found in the LICENSE file or at
# https://opensource.org/licenses/MIT.

project('cipherbench', 'c',
        default_options: [
            'optimization=2',
            'warning_level=1',
            'c_std=gnu11'
        ])

conf_data = configuration_data()
conf_data.set10('SYMBOLS_HAVE_UNDERSCORE_PREFIX',
    meson.get_compiler('c').symbols_have_underscore_prefix())
configure_file(output : 'cbconfig.h', configuration : conf_data)
include_dirs = [
    include_directories('.'),
    include_directories('src'),
    include_directories('tests'),
    include_directories('../test_vectors/converted/cstruct'),
    include_directories('../third_party/linux-kernel')
]
add_project_arguments('-Wno-pointer-sign', '-fno-strict-aliasing', '-fwrapv',
                      language : 'c')

modes_src = [
    'src/aes.c',
    'src/chctr2.c',
    'src/hctr2.c',
    'src/hctr2_twkd.c',
    'src/polyval.c',
    'src/polyval_xor.c',
    'src/xctr.c',
    '../third_party/linux-kernel/aes_ti.c',
    '../third_party/linux-kernel/gf128.c',
]

if host_machine.system() == 'windows'
    modes_src += ['src/simd_stubs.c']
endif

extra_libs = []
if host_machine.cpu_family() == 'aarch64'
    modes_src += [
        'src/aarch64/polyval-ce-core.S',
        '../third_party/linux-kernel/aarch64/aes-ce.S',
    ]
endif
if host_machine.cpu_family() == 'x86_64'
    if host_machine.system() != 'windows'
        modes_src += [
            'src/x86_64/polyval-clmulni_asm.S',
            '../third_party/linux-kernel/x86_64/aes_ctrby8_avx-x86_64.S',
            '../third_party/linux-kernel/x86_64/aesni-intel_asm.S',
        ]
    endif
    if host_machine.system() != 'windows'
        extra_libs += static_library('polyval_xor_clmul',
            'src/x86_64/polyval_xor_clmul.c',
            include_directories : include_dirs,
            c_args : ['-mpclmul'])
    endif
endif

# Internal artifact library: not installed, no ABI stability promise.
modes_lib = static_library('hctr2_modes', modes_src,
    include_directories : include_dirs)

official_vectors = ['../test_vectors/converted/cstruct/hctr2_testvecs.c']

prog_python = find_program('python3')
conf_vectors_c = custom_target('conformance_vectors',
    input : ['../tools/vectors_to_c.py',
             '../test_vectors/reference/v1/chctr2-aes256-polyval-v1.json',
             '../test_vectors/reference/v1/hctr2-twkd-cenc126-aes256-polyval-v1.json'],
    output : 'conformance_vectors.c',
    command : [prog_python, '@INPUT0@', '@INPUT1@', '@INPUT2@', '@OUTPUT@'])

cipherbench = executable('cipherbench',
    ['src/cipherbench.c', 'bench/registrations.c', conf_vectors_c] + official_vectors,
    include_directories : include_dirs,
    link_with : [modes_lib] + extra_libs)
benchmark('benchmark', cipherbench)

conformance = executable('conformance_tests',
    ['tests/conformance.c', conf_vectors_c] + official_vectors,
    include_directories : include_dirs,
    link_with : [modes_lib] + extra_libs)
test('conformance', conformance)
