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
