// Rozwijanie i zwijanie szczegółów artefaktów kliknięciem w wiersz tabeli.
// Delegacja zdarzeń: działa także po podmianie tabeli przez odpytywanie htmx.
const otwarte = new Set();

function rozwin(wiersz, cel) {
  htmx.ajax("GET", wiersz.dataset.szczegoly, { target: cel });
  wiersz.classList.add("otwarty");
}

document.addEventListener("click", (zdarzenie) => {
  const wiersz = zdarzenie.target.closest("tr[data-szczegoly]");
  if (!wiersz || zdarzenie.target.closest("a")) return;
  const cel = document.getElementById(wiersz.dataset.cel);
  if (!cel) return;
  if (cel.innerHTML.trim()) {
    cel.innerHTML = "";
    wiersz.classList.remove("otwarty");
    otwarte.delete(wiersz.dataset.cel);
  } else {
    rozwin(wiersz, cel);
    otwarte.add(wiersz.dataset.cel);
  }
});

// Zmiana sekcji podmienia #glowna — wcześniej otwarte wiersze już nie dotyczą widoku
document.addEventListener("htmx:beforeSwap", (zdarzenie) => {
  if (zdarzenie.detail.target && zdarzenie.detail.target.id === "glowna") otwarte.clear();
});

// Odpytywanie podmienia tabelę artefaktów (OOB) — ponownie rozwijamy wiersze otwarte wcześniej.
// Zdarzenie przychodzi raz na każdy podmieniony element; klasa „otwarty” chroni przed zdublowaniem.
document.addEventListener("htmx:oobAfterSwap", () => {
  otwarte.forEach((id) => {
    const wiersz = document.querySelector(`tr[data-cel="${CSS.escape(id)}"]`);
    const cel = document.getElementById(id);
    if (wiersz && cel && !wiersz.classList.contains("otwarty") && !cel.innerHTML.trim()) rozwin(wiersz, cel);
  });
});

// Potwierdzenie przed wysłaniem formularza (np. usunięcie analizy) — bez JS inline, zgodnie z CSP.
document.addEventListener("submit", (zdarzenie) => {
  const formularz = zdarzenie.target;
  const pytanie = formularz.dataset && formularz.dataset.potwierdz;
  // data-potwierdz-jesli: pytaj tylko, gdy zaznaczone jest wskazane pole (np. „Wyślij też do Joe”)
  const warunek = formularz.dataset && formularz.dataset.potwierdzJesli;
  if (warunek && !(formularz.elements[warunek] && formularz.elements[warunek].checked)) return;
  if (pytanie && !window.confirm(pytanie)) zdarzenie.preventDefault();
});

// Skróty klawiszowe: litera werdyktu (P, M, B…) klika przycisk werdyktu, „/” przenosi do wyszukiwarki.
// Pomijane w polach formularzy i z modyfikatorami, żeby nie przechwytywać pisania ani skrótów przeglądarki.
document.addEventListener("keydown", (zdarzenie) => {
  if (zdarzenie.ctrlKey || zdarzenie.metaKey || zdarzenie.altKey || zdarzenie.repeat) return;
  const cel = zdarzenie.target;
  if (cel instanceof Element && cel.closest("input, textarea, select, [contenteditable]")) return;
  if (zdarzenie.key === "/") {
    const szukaj = document.querySelector("form.szukaj input[type=search]");
    if (szukaj) { zdarzenie.preventDefault(); szukaj.focus(); }
    return;
  }
  if (zdarzenie.key.length !== 1) return;
  const przycisk = document.querySelector(
    `form.werdykt button[data-skrot="${CSS.escape(zdarzenie.key.toUpperCase())}"]`);
  if (przycisk) { zdarzenie.preventDefault(); przycisk.click(); }
});
