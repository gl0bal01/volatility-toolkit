# Bash completion for vol-analyze
# Installed by `make install`, or source this file from ~/.bashrc

_vol_analyze() {
    local cur prev opts
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"

    opts="--os -o --output -j --jobs --symbols --isf-url --dump-registry --dump-files --extract-strings --json --interactive --no-color -h --help -v --version"

    # COMP_WORDBREAKS splits "https://..." at ':', so read the URL and the
    # option before it from the raw line, and offer only the part after the
    # last ':' (the part readline replaces). URLs never contain spaces.
    local line="${COMP_LINE:0:COMP_POINT}" word before
    word="${line##*[[:space:]]}"
    before="${line%"$word"}"
    before="${before%"${before##*[![:space:]]}"}"
    if [[ "${before##*[[:space:]]}" == --isf-url ]]; then
        mapfile -t COMPREPLY < <(compgen -W "https://github.com/Abyss-W4tcher/volatility3-symbols/raw/master/banners/banners.json" -- "$word")
        if (( ${#COMPREPLY[@]} )) && [[ "$COMP_WORDBREAKS" == *:* && "$word" == *:* ]]; then
            local colon_prefix="${word%"${word##*:}"}"
            COMPREPLY=("${COMPREPLY[@]#"$colon_prefix"}")
        fi
        return 0
    fi

    # mapfile keeps paths containing spaces as single candidates.
    case "$prev" in
        --os)
            mapfile -t COMPREPLY < <(compgen -W "windows linux mac auto" -- "$cur")
            return 0
            ;;
        -o|--output|--symbols)
            compopt -o filenames
            mapfile -t COMPREPLY < <(compgen -d -- "$cur")
            return 0
            ;;
        -j|--jobs)
            # Free-form integer; offer a sane range as hints
            mapfile -t COMPREPLY < <(compgen -W "$(seq 1 32)" -- "$cur")
            return 0
            ;;
    esac

    if [[ "$cur" == -* ]]; then
        mapfile -t COMPREPLY < <(compgen -W "$opts" -- "$cur")
    else
        # Complete memory dump files (the @(...) pattern needs extglob);
        # -o filenames makes readline escape spaces and append / to dirs.
        compopt -o filenames
        shopt -q extglob || local _restore_extglob=1
        shopt -s extglob
        mapfile -t COMPREPLY < <(compgen -f -X '!*.@(raw|vmem|dmp|mem|bin|img|lime)' -- "$cur")
        [[ -n "${_restore_extglob:-}" ]] && shopt -u extglob
        mapfile -t -O "${#COMPREPLY[@]}" COMPREPLY < <(compgen -d -- "$cur")
    fi
}

complete -F _vol_analyze vol-analyze
complete -F _vol_analyze vol-analyze.sh
