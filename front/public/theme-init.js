// Applique le thème AVANT le premier rendu (évite l'éclair blanc). Fichier externe : la CSP interdit les scripts en ligne.
// Préférence : « light » | « dark » | « system » (défaut). Aucune donnée sensible : seulement ce choix.
;(function () {
  var mode = 'system'
  try {
    var saved = window.localStorage.getItem('lasthop-theme')
    if (saved === 'light' || saved === 'dark' || saved === 'system') mode = saved
  } catch (e) {
    /* stockage indisponible : thème système */
  }
  var dark = mode === 'dark' || (mode === 'system' && window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches)
  document.documentElement.setAttribute('data-theme', dark ? 'dark' : 'light')
})()
