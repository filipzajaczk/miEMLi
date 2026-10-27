// Rozwijanie i zwijanie szczegółów IOC kliknięciem w wiersz tabeli.
// Delegacja zdarzeń: działa także po podmianie tabeli przez odpytywanie htmx.
document.addEventListener("click", (zdarzenie) => {
  const wiersz = zdarzenie.target.closest("tr[data-szczegoly]");
  if (!wiersz || zdarzenie.target.closest("a")) return;
  const cel = document.getElementById(wiersz.dataset.cel);
  if (!cel) return;
  if (cel.innerHTML.trim()) {
    cel.innerHTML = "";
    wiersz.classList.remove("otwarty");
  } else {
    htmx.ajax("GET", wiersz.dataset.szczegoly, { target: cel });
    wiersz.classList.add("otwarty");
  }
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
