# Bash completion for vol-analyze
# Source this file or copy to /etc/bash_completion.d/

_vol_analyze() {
    local cur prev opts
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"

    opts="--os -o --output -j --jobs --dump-registry --dump-files --extract-strings --json --interactive --no-color -h --help -v --version"

    case "$prev" in
        --os)
            COMPREPLY=( $(compgen -W "windows linux mac auto" -- "$cur") )
            return 0
            ;;
        -o|--output)
            COMPREPLY=( $(compgen -d -- "$cur") )
            return 0
            ;;
        -j|--jobs)
            # Free-form integer; offer a sane range as hints
            COMPREPLY=( $(compgen -W "$(seq 1 32)" -- "$cur") )
            return 0
            ;;
    esac

    if [[ "$cur" == -* ]]; then
        COMPREPLY=( $(compgen -W "$opts" -- "$cur") )
    else
        # Complete memory dump files
        COMPREPLY=( $(compgen -f -X '!*.@(raw|vmem|dmp|mem|bin|img|lime)' -- "$cur") )
        COMPREPLY+=( $(compgen -d -- "$cur") )
    fi
}

complete -F _vol_analyze vol-analyze
complete -F _vol_analyze vol-analyze.sh
