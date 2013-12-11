#!/bin/bash

grep '        """\|^   #' gazouilleur/bot.py |
  grep -v '^   # ----' |
  sed 's/_/\_/g' | sed 's/*/\*/g' | sed 's/&/\&amp;/g' |
  sed 's/   # /\n# /' |           # category title
  sed 's/   ##/ */' |           # category infos
  sed "s/\(Exclude regexp\s*:\)\s*\('[^']\+'\)\s*\(.*\)$/**\1** \`\2\`\n * **List :**/" |  # emphaze infos + title list commands
  sed 's/\s*"""\(.*\) : /\n  + \`\1\`\n\n     > /g' |         # codize command + quote descr
  sed 's#.\(/[A-Z]\+\)\+"""#.\n     > > restricted to \1#' |   # add command rights info
  sed 's/\([^[|`]\)<\([^>]\+\)>\([^]|`]\)\([^<[`]\|$\)/\1\&lt;\2\&gt;\3\4/g' |   # encode special markdown chars                    
  sed 's/"""$//' > LIST_COMMANDS.md

