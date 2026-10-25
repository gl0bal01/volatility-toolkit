#compdef vol-analyze vol-analyze.sh
# Zsh completion for vol-analyze
# Installed by `make install`, or copy into a directory in your $fpath as _vol-analyze

_vol-analyze() {
    local -a opts
    opts=(
        '--os[Target OS]:os:(windows linux mac auto)'
        '-o[Output directory]:directory:_directories'
        '--output[Output directory]:directory:_directories'
        '-j[Max parallel plugins]:jobs:_message "positive integer"'
        '--jobs[Max parallel plugins]:jobs:_message "positive integer"'
        '--dump-registry[Dump registry hives (Windows only)]'
        '--dump-files[Dump files from memory (Windows only)]'
        '--extract-strings[Extract and categorize IOC strings]'
        '--json[Generate JSON summary report]'
        '--interactive[Enable interactive prompts]'
        '--no-color[Disable colored output]'
        '-h[Show help]'
        '--help[Show help]'
        '-v[Show version]'
        '--version[Show version]'
    )

    _arguments -s $opts '*:memory dump:_files -g "*.(raw|vmem|dmp|mem|bin|img|lime)"'
}

_vol-analyze "$@"
