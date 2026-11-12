
# -*- coding: utf-8 -*-

import csv
import subprocess
import sys
import io
import json
from html import escape
from pathlib import Path

import altair as alt
import pandas as pd
import streamlit as st


# ==========================================
# CONFIGURATION
# ==========================================

ROOT = Path(__file__).resolve().parents[1]
ALERTS_DIR = ROOT / "alerts"

SOURCES = {
    "Incidents": "incidents.json",
    "Port scan": "portscan_alerts.json",
    "HTTP flood": "http_flood_alerts.json",
}

st.set_page_config(
    page_title="DARKTRACE LAB | SOC",
    page_icon="🛡️",
    layout="wide"
)


# ==========================================
# DESIGN GLASSMORPHISM
# ==========================================

st.html("""
<style>

.stApp {
    background:
        radial-gradient(
            ellipse at 78% 14%,
            #182f48 0,
            transparent 42%
        ),
        radial-gradient(
            ellipse at 5% 54%,
            #332c25 0,
            transparent 36%
        ),
        #15181d;
}

[data-testid="stMainBlockContainer"] {
    max-width: 87rem;
    padding-top: 5rem;
}

/* NAVBAR */

.st-key-soc_nav {
    position: sticky;
    top: 3.75rem;
    z-index: 20;
}

.soc-nav {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: .4rem 1.25rem;

    padding: .75rem 1.2rem;
    border-radius: 1rem;

    background: linear-gradient(
        125deg,
        #435a757a,
        #202b3ae8 60%
    );

    border: 1px solid #ffffff29;

    backdrop-filter: blur(18px);
    -webkit-backdrop-filter: blur(18px);

    box-shadow:
        inset 0 1px 0 #c4ddff3d,
        0 12px 32px #0005;
}

.soc-nav strong {
    margin-right: auto;
    color: #f4ebdc;
    letter-spacing: .1em;
}

.soc-nav a {
    color: #c4e1ff;
    text-decoration: none;
    padding: .4rem .7rem;
    border-radius: .5rem;
    transition: .25s;
}

.soc-nav a:hover {
    color: white;
    background: #72b6ff29;
}

.soc-nav a:focus-visible {
    outline: 2px solid #71bcff;
    outline-offset: 3px;
}

/* HERO MACBOOK */

.soc-hero {
    perspective: 1000px;
    margin: 1.5rem 0 3rem;
}

.soc-screen {
    border: 7px solid #333b46;
    border-radius: 1.5rem;

    padding: clamp(1.25rem, 5vw, 4rem);

    background:
        radial-gradient(
            ellipse at 92% 10%,
            #2773b879,
            transparent 55%
        ),
        repeating-linear-gradient(
            90deg,
            #81bfff0c 0 1px,
            transparent 1px 38px
        ),
        repeating-linear-gradient(
            0deg,
            #81bfff0c 0 1px,
            transparent 1px 38px
        ),
        #192331;

    box-shadow:
        inset 0 1px 0 #c4ddff55,
        0 28px 65px #02060b99;
}

.soc-screen h1 {
    color: #f4ebdc;
    font-size: clamp(2rem, 6vw, 4.5rem);
    line-height: 1.04;
    margin: .6rem 0 1rem;
}

.soc-screen p {
    color: #b6c7d8;
    font-size: 1.05rem;
    max-width: 44rem;
}

.soc-kicker {
    color: #9fd0ff;
    font-size: .8rem;
    font-weight: 700;
    letter-spacing: .16em;
}

.soc-base {
    height: .65rem;
    background: #626976;
    border-radius: 0 0 50% 50%;
    margin: 0 -1%;
}

/* KPI CARDS */

.soc-grid {
    display: grid;

    grid-template-columns:
        repeat(
            auto-fit,
            minmax(min(100%, 12rem), 1fr)
        );

    gap: 1rem;
}

.soc-card {
    position: relative;
    isolation: isolate;

    margin-top: 1rem;
    padding: 1.2rem;

    border-radius: 1rem;

    color: #f4ebdc;

    background:
        radial-gradient(
            ellipse at 15% 0%,
            #8fc6ff38,
            transparent 62%
        ),
        linear-gradient(
            155deg,
            #394c65 0%,
            #202c3e 44%,
            #181f2a 100%
        );

    border: 1px solid #c4ddff42;

    backdrop-filter: blur(18px);
    -webkit-backdrop-filter: blur(18px);

    box-shadow:
        inset 0 1px 0 #e3efff55,
        inset 0 -1px 0 #0006,
        0 14px 28px #0005;
}

.soc-card::before {
    content: "";

    position: absolute;

    left: 50%;
    top: -1rem;

    height: 1rem;
    width: 2px;

    background: #71bcff;
}

.soc-card::after {
    content: "";

    position: absolute;
    inset: 0;

    z-index: -1;
    pointer-events: none;

    border-radius: inherit;

    background: linear-gradient(
        116deg,
        transparent 26%,
        #d5edff30 45%,
        #e4f2ff10 52%,
        transparent 66%
    );

    background-size: 220% 100%;
    background-position: 48% 0;
}

.soc-card span {
    color: #d6dce6;
    font-size: .9rem;
}

.soc-card strong {
    display: block;
    font-size: 2.2rem;
    color: #b8dcff;
    margin-top: .4rem;
}

/* ANALYSIS PANEL */

.soc-analysis {
    padding: 1.5rem;
    border-radius: 1.2rem;

    border: 1px solid #82bdff40;

    background:
        radial-gradient(
            ellipse at top right,
            #2373ba36,
            transparent 65%
        ),
        linear-gradient(
            145deg,
            #26364b,
            #19212d
        );

    box-shadow:
        inset 0 1px 0 #d3eaff30,
        0 18px 40px #0004;

    backdrop-filter: blur(20px);
}

.soc-analysis-title {
    font-size: 1.35rem;
    font-weight: 700;
    color: #f4ebdc;
}

.soc-analysis-desc {
    color: #a9bdd1;
    margin-top: .4rem;
}

/* SECTIONS */

.soc-anchor {
    scroll-margin-top: 9rem;
    color: #f4ebdc;
    margin-top: 2.5rem;
    margin-bottom: 1.5rem;
}

/* BUTTONS */

div.stButton > button[kind="primary"] {
    background: linear-gradient(
        135deg,
        #287dff,
        #1450bc
    );

    color: white;
    border: 1px solid #8cc5ff80;
    border-radius: .8rem;

    box-shadow:
        0 8px 25px #1675ff45,
        inset 0 1px 0 #ffffff40;

    font-weight: 650;
}

div.stButton > button[kind="primary"]:hover {
    background: linear-gradient(
        135deg,
        #4496ff,
        #2367e2
    );

    box-shadow: 0 12px 35px #1675ff70;
}

/* SCROLL ANIMATIONS */

@media (prefers-reduced-motion: no-preference) {

    [data-testid="stMain"] {
        scroll-behavior: smooth;
    }

    @supports (animation-timeline: view()) {

        .soc-screen {
            transform-origin: bottom center;
            animation: soc-tilt linear both;
            animation-timeline: view();
            animation-range: exit 0% exit 85%;
        }

        .soc-card {
            animation: soc-rise linear both;
            animation-timeline: view();
            animation-range: entry 0% entry 90%;
        }
    }
}

@keyframes soc-tilt {
    from {
        transform: rotateX(0);
    }

    to {
        transform: rotateX(-18deg) scale(.96);
    }
}

@keyframes soc-rise {
    from {
        transform: translateY(12px);
    }

    to {
        transform: translateY(0);
    }
}

@media (hover: hover) {

    .soc-card:hover {
        border-color: #9ed0ff;

        box-shadow:
            inset 0 1px 0 #e3efff80,
            0 16px 34px #0006,
            0 0 25px #339aff35;
    }
}

@media (hover: hover)
and (prefers-reduced-motion: no-preference) {

    .soc-card {
        transition:
            translate .25s ease,
            box-shadow .25s ease,
            border-color .25s ease;
    }

    .soc-card:hover {
        translate: 0 -5px;
    }
}

</style>
""")


# ==========================================
# DATA FUNCTIONS
# ==========================================

def read_source(filename):

    path = ALERTS_DIR / filename

    try:
        records = json.loads(
            path.read_text(encoding="utf-8-sig")
        )

        if (
            not isinstance(records, list)
            or any(
                not isinstance(row, dict)
                for row in records
            )
        ):
            raise ValueError(
                "Structure JSON inattendue"
            )

    except (OSError, ValueError):
        st.warning(
            f"{filename} est indisponible ou invalide."
        )
        return []

    return records


def field(record, key):

    value = record.get(key)

    return "" if value is None else str(value)


def csv_cell(value):

    if isinstance(value, (list, dict)):
        value = json.dumps(
            value,
            ensure_ascii=False
        )

    if isinstance(value, str):

        if (
            value.startswith(("\t", "\r", "\n"))
            or value.lstrip().startswith(
                ("=", "+", "-", "@")
            )
        ):
            return "'" + value

    return value


def exports(records, scope):

    buffer = io.StringIO(newline="")

    columns = dict.fromkeys(
        key
        for row in records
        for key in row
    )

    writer = csv.writer(buffer)

    writer.writerow(
        [csv_cell(key) for key in columns]
    )

    writer.writerows(
        [
            csv_cell(row.get(key))
            for key in columns
        ]
        for row in records
    )

    csv_col, json_col = st.columns(2)

    csv_col.download_button(
        "Télécharger CSV",
        buffer.getvalue().encode("utf-8-sig"),
        f"{scope}.csv",
        "text/csv",
        key=f"{scope}_csv"
    )

    json_col.download_button(
        "Télécharger JSON",
        json.dumps(
            records,
            ensure_ascii=False,
            indent=2
        ),
        f"{scope}.json",
        "application/json",
        key=f"{scope}_json"
    )


def section(anchor, title):

    st.html(
        f'<h2 class="soc-anchor" '
        f'id="{escape(anchor, quote=True)}">'
        f'{escape(title)}</h2>'
    )


def alert_chart(records, metric, label):

    points = pd.DataFrame([
        {
            "UTC": row.get("timestamp"),
            label: row.get(metric),
            "Seuil": row.get("threshold"),
            "Fenêtre (s)": row.get("window_seconds"),
            "Source": row.get("source_ip"),
            "Destination": row.get("destination_ip"),
        }
        for row in records
    ])

    if points.empty:
        st.caption(
            "Aucune alerte correspondante."
        )
        return

    points["UTC"] = pd.to_datetime(
        points["UTC"],
        errors="coerce",
        utc=True,
        format="mixed"
    )

    points[label] = pd.to_numeric(
        points[label],
        errors="coerce"
    )

    points = points.dropna(
        subset=["UTC", label]
    )

    if points.empty:
        st.caption(
            "Aucune mesure horodatée exploitable."
        )
        return

    chart = (
        alt.Chart(points)
        .mark_circle(
            color="#339aff",
            size=85,
            opacity=.9
        )
        .encode(
            x=alt.X(
                "UTC:T",
                scale=alt.Scale(type="utc")
            ),
            y=alt.Y(
                field=label,
                type="quantitative"
            ),
            tooltip=[
                alt.Tooltip(
                    "UTC:T",
                    format="%Y-%m-%d %H:%M:%S",
                    formatType="utc"
                ),
                alt.Tooltip(
                    field=label,
                    type="quantitative"
                ),
                "Seuil:Q",
                "Fenêtre (s):Q",
                "Source:N",
                "Destination:N",
            ]
        )
        .properties(
            height=235,
            description=(
                f"{label} pour chaque alerte UTC."
            )
        )
    )

    st.altair_chart(
        chart,
        width="stretch"
    )


# ==========================================
# NAVIGATION
# ==========================================

with st.container(key="soc_nav"):

    st.html("""
    <nav class="soc-nav" aria-label="Navigation SOC">
        <strong>DARKTRACE / LAB</strong>

        <a href="#analyse">Analyse</a>
        <a href="#synthese">Synthèse</a>
        <a href="#incidents">Incidents</a>
        <a href="#alertes">Alertes</a>
    </nav>
    """)


# ==========================================
# HERO
# ==========================================

st.html("""
<div class="soc-hero">

    <div class="soc-screen">

        <div class="soc-kicker">
            SECURITY OPERATIONS CENTER
            · ANALYSE HORS LIGNE
        </div>

        <h1>Console de détection</h1>

        <p>
            Analysez le trafic réseau, détectez les
            activités suspectes et explorez les
            incidents de sécurité.
        </p>

    </div>

    <div class="soc-base" aria-hidden="true"></div>

</div>
""")


# ==========================================
# ANALYSE IDS
# ==========================================

section("analyse", "Analyse réseau")

st.html("""
<div class="soc-analysis">

    <div class="soc-kicker">
        DARKTRACE ENGINE · PCAP ANALYSIS
    </div>

    <div class="soc-analysis-title">
        Network Security Scanner
    </div>

    <div class="soc-analysis-desc">
        Lancez les détecteurs PortScan et HTTP Flood
        sur la capture réseau configurée.
    </div>

</div>
""")

st.write("")

st.caption(
    "Mode actuel : analyse PCAP hors ligne. "
    "Le fichier utilisé est celui configuré "
    "dans les scripts de détection."
)

col_a, col_b = st.columns([2, 1])

with col_a:

    start_analysis = st.button(
        "▶ Démarrer l'analyse IDS",
        type="primary",
        use_container_width=True,
        key="start_ids_analysis"
    )

with col_b:

    st.metric(
        "Détecteurs actifs",
        "2",
        help="PortScan et HTTP Flood"
    )


if start_analysis:

    with st.status(
        "Analyse réseau en cours...",
        expanded=True
    ) as status:

        st.write(
            "Initialisation du moteur DARKTRACE LAB..."
        )

        st.write(
            "Exécution des détecteurs et "
            "du moteur de corrélation..."
        )

        try:

            result = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "main.py")
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=1800
            )

            if result.returncode == 0:

                status.update(
                    label="Analyse IDS terminée",
                    state="complete"
                )

                st.success(
                    "Analyse terminée avec succès ! "
                    "Les résultats sont disponibles "
                    "dans le dashboard."
                )

                st.session_state[
                    "last_analysis_success"
                ] = True

                with st.expander(
                    "Afficher le rapport d'exécution"
                ):

                    st.code(
                        result.stdout[-12000:],
                        language="text"
                    )

            else:

                status.update(
                    label="Échec de l'analyse",
                    state="error"
                )

                st.error(
                    "Le moteur IDS a échoué "
                    f"(code {result.returncode})."
                )

                st.code(
                    (
                        result.stderr
                        or result.stdout
                    )[-5000:],
                    language="text"
                )

        except subprocess.TimeoutExpired:

            status.update(
                label="Délai d'analyse dépassé",
                state="error"
            )

            st.error(
                "L'analyse a dépassé 30 minutes."
            )

        except OSError as error:

            status.update(
                label="Impossible de lancer l'analyse",
                state="error"
            )

            st.error(str(error))


# ==========================================
# CHARGEMENT DES RESULTATS
# ==========================================

data = {
    name: read_source(filename)
    for name, filename in SOURCES.items()
}

all_incidents = data["Incidents"]

all_alerts = (
    data["Port scan"]
    + data["HTTP flood"]
)

all_records = (
    all_incidents
    + all_alerts
)


# ==========================================
# SYNTHESE
# ==========================================

section("synthese", "Synthèse")

with st.expander(
    "Filtres",
    expanded=True
):

    left, right = st.columns(2)

    selected = {}

    for column, key, label in (
        (left, "detector", "Détecteurs"),
        (right, "severity", "Sévérités")
    ):

        options = sorted(
            {
                field(row, key)
                for row in all_records
            } - {""}
        )

        selected[key] = column.multiselect(
            label,
            options,
            help="Vide = toutes les valeurs."
        )

    query = st.text_input(
        "Recherche par IP ou identifiant d'incident"
    ).strip().casefold()


def matches(row):

    return all(
        not values
        or field(row, key) in values
        for key, values in selected.items()
    )


incidents = [
    row
    for row in all_incidents
    if matches(row)
    and any(
        query in field(row, key).casefold()
        for key in (
            "incident_id",
            "source_ip",
            "destination_ip"
        )
    )
]


incident_ids = [
    row
    for row in incidents
    if query
    and query in field(
        row,
        "incident_id"
    ).casefold()
]


def linked(alert, incident):

    for key in (
        "detector",
        "source_ip",
        "destination_ip"
    ):

        if (
            not field(alert, key)
            or field(alert, key)
            != field(incident, key)
        ):
            return False

    timestamp, start, end = pd.to_datetime(
        [
            alert.get("timestamp"),
            incident.get("first_seen"),
            incident.get("last_seen")
        ],
        utc=True,
        errors="coerce",
        format="mixed"
    )

    return (
        pd.notna(timestamp)
        and pd.notna(start)
        and pd.notna(end)
        and start <= timestamp <= end
    )


def visible_alert(row):

    return matches(row) and (
        query in field(
            row,
            "source_ip"
        ).casefold()

        or query in field(
            row,
            "destination_ip"
        ).casefold()

        or any(
            linked(row, incident)
            for incident in incident_ids
        )
    )


alerts_by_source = {
    name: [
        row
        for row in data[name]
        if visible_alert(row)
    ]
    for name in (
        "Port scan",
        "HTTP flood"
    )
}

alerts = (
    alerts_by_source["Port scan"]
    + alerts_by_source["HTTP flood"]
)


metrics = [
    (
        "Incidents",
        len(incidents)
    ),
    (
        "Alertes brutes",
        len(alerts)
    ),
    (
        "Incidents HIGH",
        sum(
            field(row, "severity") == "HIGH"
            for row in incidents
        )
    ),
    (
        "Sources distinctes",
        len(
            {
                field(row, "source_ip")
                for row in incidents + alerts
            } - {""}
        )
    ),
]


st.html(
    '<div class="soc-grid">'
    + "".join(
        (
            '<div class="soc-card">'
            f'<span>{escape(label)}</span>'
            f'<strong>{value}</strong>'
            '</div>'
        )
        for label, value in metrics
    )
    + "</div>"
)

st.caption(
    "Indicateurs calculés sur la sélection actuelle."
)


# ==========================================
# INCIDENTS
# ==========================================

section(
    "incidents",
    "Incidents consolidés"
)

if incidents:

    summary_fields = {
        "incident_id": "ID",
        "detector": "Détecteur",
        "severity": "Sévérité",
        "source_ip": "Source",
        "destination_ip": "Destination",
        "first_seen": "Début UTC",
        "last_seen": "Fin UTC",
        "alert_count": "Alertes",
        "status": "Statut",
    }

    st.dataframe(
        [
            {
                label: row.get(key)
                for key, label
                in summary_fields.items()
            }
            for row in incidents
        ],
        hide_index=True,
        width="stretch"
    )

    exports(
        incidents,
        "incidents"
    )

    for row in sorted(
        incidents,
        key=lambda item: field(
            item,
            "first_seen"
        )
    ):

        title = " · ".join(
            field(row, key)
            for key in (
                "incident_id",
                "detector",
                "severity"
            )
        )

        with st.expander(
            title or "Incident"
        ):

            if (
                row.get(
                    "max_requests_per_window"
                ) is not None
            ):

                st.text(
                    "Maximum GET par fenêtre "
                    "dans les alertes : "
                    f"{row['max_requests_per_window']}"
                )

            if (
                row.get(
                    "max_distinct_ports_per_window"
                ) is not None
            ):

                st.text(
                    "Ports distincts au "
                    "déclenchement : "
                    f"{row['max_distinct_ports_per_window']}"
                )

            st.json(
                row,
                expanded=False
            )

else:

    st.info(
        "Aucun incident dans cette sélection."
    )


# ==========================================
# ALERTES BRUTES
# ==========================================

section(
    "alertes",
    "Alertes brutes"
)

st.caption(
    "Chaque point représente une alerte enregistrée. "
    "Les mesures du trafic hors alertes "
    "ne figurent pas dans ces graphiques."
)


for name, metric, label in (
    (
        "HTTP flood",
        "requests_per_window",
        "Requêtes GET par fenêtre"
    ),
    (
        "Port scan",
        "distinct_ports_per_window",
        "Ports distincts par fenêtre"
    ),
):

    with st.container(border=True):

        st.subheader(name)

        records = alerts_by_source[name]

        alert_chart(
            records,
            metric,
            label
        )

        if records:

            with st.expander(
                "Consulter les mesures et les seuils"
            ):

                st.dataframe(
                    records,
                    hide_index=True,
                    width="stretch"
                )

            exports(
                records,
                name.lower().replace(
                    " ",
                    "_"
                )
            )


# ==========================================
# FOOTER
# ==========================================

st.divider()

st.caption(
    "DARKTRACE LAB · CIC-IDS2017 · "
    "Analyse réseau hors ligne · "
    "Horodatages en UTC"
)
