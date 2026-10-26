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
