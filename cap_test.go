// Copyright (c) 2019 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

package cap_test

import (
	"os"
	"strings"
	"testing"

	"github.com/tannerryan/cap"
)

// assertEqual reports a labeled string mismatch.
func assertEqual(t *testing.T, name, expected, actual string) {
	t.Helper()
	if expected != actual {
		t.Errorf("%s: got %q, want %q", name, actual, expected)
	}
}

// parseFixture reads and parses one XML fixture.
func parseFixture(t *testing.T, name string) *cap.Alert {
	t.Helper()
	data, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	alert, err := cap.ParseCAP(data)
	if err != nil {
		t.Fatal(err)
	}
	return alert
}

// TestOASISHomelandAlert checks the Homeland Security example from CAP 1.2.
func TestOASISHomelandAlert(t *testing.T) {
	alert := parseFixture(t, "testing/Oasis_HomelandAlert.xml")

	// Alert section
	assertEqual(t, "Homeland identifier", "43b080713727", alert.Identifier)
	assertEqual(t, "Homeland sender", "hsas@dhs.gov", alert.Sender)
	assertEqual(t, "Homeland sent", "2003-04-02T14:39:01-05:00", alert.Sent.String())
	assertEqual(t, "Homeland status", "Actual", alert.Status.String())
	assertEqual(t, "Homeland message type", "Alert", alert.MsgType.String())
	assertEqual(t, "Homeland scope", "Public", alert.Scope.String())

	// Info section
	info := alert.Info[0] // only one info section
	assertEqual(t, "Homeland info category", "Security", info.Category[0].String())
	assertEqual(t, "Homeland info event", "Homeland Security Advisory System Update", info.Event)
	assertEqual(t, "Homeland info urgency", "Immediate", info.Urgency.String())
	assertEqual(t, "Homeland info severity", "Severe", info.Severity.String())
	assertEqual(t, "Homeland info certainty", "Likely", info.Certainty.String())
	assertEqual(t, "Homeland info sender name", "U.S. Government, Department of Homeland Security", info.SenderName)
	assertEqual(t, "Homeland info headline", "Homeland Security Sets Code ORANGE", info.Headline)
	assertEqual(t, "Homeland info description", "The Department of Homeland Security has elevated the Homeland Security Advisory System threat level to ORANGE / High in response to intelligence which may indicate a heightened threat of terrorism.", info.Description)
	assertEqual(t, "Homeland info instruction", " A High Condition is declared when there is a high risk of terrorist attacks. In addition to the Protective Measures taken in the previous Threat Conditions, Federal departments and agencies should consider agency-specific Protective Measures in accordance with their existing plans.", info.Instruction)
	assertEqual(t, "Homeland info web", "http://www.dhs.gov/dhspublic/display?theme=29", info.Web)

	// Info parameters
	infoParams := info.Parameter[0] // only one parameter
	assertEqual(t, "Homeland info parameter value name", "HSAS", infoParams.ValueName)
	assertEqual(t, "Homeland info parameter value", "ORANGE", infoParams.Value)

	// Info resources
	infoResources := info.Resource[0] // only one resource
	assertEqual(t, "Homeland info resource description", "Image file (GIF)", infoResources.ResourceDesc)
	assertEqual(t, "Homeland info resource MIME type", "image/gif", infoResources.MimeType)
	assertEqual(t, "Homeland info resource URI", "http://www.dhs.gov/dhspublic/getAdvisoryImage", infoResources.URI)

	// Info areas
	infoAreas := info.Area[0] // only one area
	assertEqual(t, "Homeland info area description", "U.S. nationwide and interests worldwide", infoAreas.AreaDesc)
}

// TestOASISThunderstormWarning checks the thunderstorm example from CAP 1.2.
func TestOASISThunderstormWarning(t *testing.T) {
	alert := parseFixture(t, "testing/Oasis_ThunderstormWarning.xml")

	// Alert section
	assertEqual(t, "Thunderstorm identifier", "KSTO1055887203", alert.Identifier)
	assertEqual(t, "Thunderstorm sender", "KSTO@NWS.NOAA.GOV", alert.Sender)
	assertEqual(t, "Thunderstorm sent", "2003-06-17T14:57:00-07:00", alert.Sent.String())
	assertEqual(t, "Thunderstorm status", "Actual", alert.Status.String())
	assertEqual(t, "Thunderstorm message type", "Alert", alert.MsgType.String())
	assertEqual(t, "Thunderstorm scope", "Public", alert.Scope.String())

	// Info section
	info := alert.Info[0] // only one info section
	assertEqual(t, "Thunderstorm info category", "Met", info.Category[0].String())
	assertEqual(t, "Thunderstorm info event", "SEVERE THUNDERSTORM", info.Event)
	assertEqual(t, "Thunderstorm info response type", "Shelter", info.ResponseType[0].String())
	assertEqual(t, "Thunderstorm info urgency", "Immediate", info.Urgency.String())
	assertEqual(t, "Thunderstorm info severity", "Severe", info.Severity.String())
	assertEqual(t, "Thunderstorm info certainty", "Observed", info.Certainty.String())
	assertEqual(t, "Thunderstorm info expires", "2003-06-17T16:00:00-07:00", info.Expires.String())
	assertEqual(t, "Thunderstorm info sender name", "NATIONAL WEATHER SERVICE SACRAMENTO CA", info.SenderName)
	assertEqual(t, "Thunderstorm info headline", "SEVERE THUNDERSTORM WARNING", info.Headline)
	assertEqual(t, "Thunderstorm info description", " AT 254 PM PDT...NATIONAL WEATHER SERVICE DOPPLER RADAR INDICATED A SEVERE THUNDERSTORM OVER SOUTH CENTRAL ALPINE COUNTY...OR ABOUT 18 MILES SOUTHEAST OF KIRKWOOD...MOVING SOUTHWEST AT 5 MPH. HAIL...INTENSE RAIN AND STRONG DAMAGING WINDS ARE LIKELY WITH THIS STORM.", info.Description)
	assertEqual(t, "Thunderstorm info instruction", "TAKE COVER IN A SUBSTANTIAL SHELTER UNTIL THE STORM PASSES.", info.Instruction)
	assertEqual(t, "Thunderstorm info contact", "BARUFFALDI/JUSKIE", info.Contact)

	// Info event code
	eventCode := info.EventCode[0] // only one event code
	assertEqual(t, "Thunderstorm info event code value name", "SAME", eventCode.ValueName)
	assertEqual(t, "Thunderstorm info event code value", "SVR", eventCode.Value)

	// Info areas
	infoAreas := info.Area[0] // only one area
	assertEqual(t, "Thunderstorm info area description", "EXTREME NORTH CENTRAL TUOLUMNE COUNTY IN CALIFORNIA, EXTREME NORTHEASTERN CALAVERAS COUNTY IN CALIFORNIA, SOUTHWESTERN ALPINE COUNTY IN CALIFORNIA", infoAreas.AreaDesc)
	assertEqual(t, "Thunderstorm info area polygon", "38.47,-120.14 38.34,-119.95 38.52,-119.74 38.62,-119.89 38.47,-120.14", infoAreas.Polygon[0].String())
	assertEqual(t, "Thunderstorm info area geocode 0 value name", "SAME", infoAreas.Geocode[0].ValueName)
	assertEqual(t, "Thunderstorm info area geocode 0 value", "006109", infoAreas.Geocode[0].Value)
	assertEqual(t, "Thunderstorm info area geocode 1 value name", "SAME", infoAreas.Geocode[1].ValueName)
	assertEqual(t, "Thunderstorm info area geocode 1 value", "006009", infoAreas.Geocode[1].Value)
	assertEqual(t, "Thunderstorm info area geocode 2 value name", "SAME", infoAreas.Geocode[2].ValueName)
	assertEqual(t, "Thunderstorm info area geocode 2 value", "006003", infoAreas.Geocode[2].Value)
}

// TestOASISEarthquakeReport checks the earthquake example from CAP 1.2.
func TestOASISEarthquakeReport(t *testing.T) {
	alert := parseFixture(t, "testing/Oasis_EarthquakeReport.xml")

	// Alert section
	assertEqual(t, "Earthquake identifier", "TRI13970876.2", alert.Identifier)
	assertEqual(t, "Earthquake sender", "trinet@caltech.edu", alert.Sender)
	assertEqual(t, "Earthquake sent", "2003-06-11T20:56:00-07:00", alert.Sent.String())
	assertEqual(t, "Earthquake status", "Actual", alert.Status.String())
	assertEqual(t, "Earthquake message type", "Update", alert.MsgType.String())
	assertEqual(t, "Earthquake scope", "Public", alert.Scope.String())
	assertEqual(t, "Earthquake references", "trinet@caltech.edu,TRI13970876.1,2003-06-11T20:30:00-07:00", alert.References.String())

	// Info section
	info := alert.Info[0] // only one info section
	assertEqual(t, "Earthquake info category", "Geo", info.Category[0].String())
	assertEqual(t, "Earthquake info event", "Earthquake", info.Event)
	assertEqual(t, "Earthquake info urgency", "Past", info.Urgency.String())
	assertEqual(t, "Earthquake info severity", "Minor", info.Severity.String())
	assertEqual(t, "Earthquake info certainty", "Observed", info.Certainty.String())
	assertEqual(t, "Earthquake info sender name", "Southern California Seismic Network (TriNet) operated by Caltech and USGS", info.SenderName)
	assertEqual(t, "Earthquake info headline", "EQ 3.4 Imperial County CA", info.Headline)
	assertEqual(t, "Earthquake info description", "A minor earthquake measuring 3.4 on the Richter scale occurred near Brawley, California at 8:30 PM Pacific Daylight Time on Wednesday, June 11, 2003. (This event has now been reviewed by a seismologist)", info.Description)
	assertEqual(t, "Earthquake info web", "http://www.trinet.org/scsn/scsn.html", info.Web)

	// Info parameters
	infoParams := info.Parameter
	assertEqual(t, "Earthquake info parameter 0 value name", "EventID", infoParams[0].ValueName)
	assertEqual(t, "Earthquake info parameter 0 value", "13970876", infoParams[0].Value)
	assertEqual(t, "Earthquake info parameter 1 value name", "Version", infoParams[1].ValueName)
	assertEqual(t, "Earthquake info parameter 1 value", "1", infoParams[1].Value)
	assertEqual(t, "Earthquake info parameter 2 value name", "Magnitude", infoParams[2].ValueName)
	assertEqual(t, "Earthquake info parameter 2 value", "3.4 Ml", infoParams[2].Value)
	assertEqual(t, "Earthquake info parameter 3 value name", "Depth", infoParams[3].ValueName)
	assertEqual(t, "Earthquake info parameter 3 value", "11.8 mi.", infoParams[3].Value)
	assertEqual(t, "Earthquake info parameter 4 value name", "Quality", infoParams[4].ValueName)
	assertEqual(t, "Earthquake info parameter 4 value", "Excellent", infoParams[4].Value)

	// Info areas
	infoArea := info.Area[0] // only one area
	assertEqual(t, "Earthquake info area description", "1 mi. WSW of Brawley, CA; 11 mi. N of El Centro, CA; 30 mi. E of OCOTILLO (quarry); 1 mi. N of the Imperial Fault", infoArea.AreaDesc)
	assertEqual(t, "Earthquake info area circle", "32.9525,-115.5527 0", infoArea.Circle[0])
}

// TestOASISAmberAlert checks the AMBER Alert example from CAP 1.2.
func TestOASISAmberAlert(t *testing.T) {
	alert := parseFixture(t, "testing/Oasis_AmberAlert.xml")

	// Alert section
	assertEqual(t, "Amber identifier", "KAR0-0306112239-SW", alert.Identifier)
	assertEqual(t, "Amber sender", "KARO@CLETS.DOJ.CA.GOV", alert.Sender)
	assertEqual(t, "Amber sent", "2003-06-11T22:39:00-07:00", alert.Sent.String())
	assertEqual(t, "Amber status", "Actual", alert.Status.String())
	assertEqual(t, "Amber message type", "Alert", alert.MsgType.String())
	assertEqual(t, "Amber source", "SW", alert.Source)
	assertEqual(t, "Amber scope", "Public", alert.Scope.String())

	// Info sections
	infoEnglish := alert.Info[0] // english
	assertEqual(t, "Amber info english language", "en-US", infoEnglish.Language)
	assertEqual(t, "Amber info english category", "Rescue", infoEnglish.Category[0].String())
	assertEqual(t, "Amber info english event", "Child Abduction", infoEnglish.Event)
	assertEqual(t, "Amber info english urgency", "Immediate", infoEnglish.Urgency.String())
	assertEqual(t, "Amber info english severity", "Severe", infoEnglish.Severity.String())
	assertEqual(t, "Amber info english certainty", "Likely", infoEnglish.Certainty.String())
	assertEqual(t, "Amber info english sender name", "Los Angeles Police Dept - LAPD", infoEnglish.SenderName)
	assertEqual(t, "Amber info english headline", "Amber Alert in Los Angeles County", infoEnglish.Headline)
	assertEqual(t, "Amber info english description", `DATE/TIME: 06/11/03, 1915 HRS.  VICTIM(S): KHAYRI DOE JR. M/B BLK/BRO 3'0", 40 LBS. LIGHT COMPLEXION.  DOB 06/24/01. WEARING RED SHORTS, WHITE T-SHIRT, W/BLUE COLLAR.  LOCATION: 5721 DOE ST., LOS ANGELES, CA.  SUSPECT(S): KHAYRI DOE SR. DOB 04/18/71 M/B, BLK HAIR, BRO EYE. VEHICLE: 81' BUICK 2-DR, BLUE (4XXX000).`, infoEnglish.Description)
	assertEqual(t, "Amber info english contact", "DET. SMITH, 77TH DIV, LOS ANGELES POLICE DEPT-LAPD AT 213 485-2389", infoEnglish.Contact)

	// Info english event codes
	infoEnglishEventCode := infoEnglish.EventCode[0] // only one event code
	assertEqual(t, "Amber info english event code value name", "SAME", infoEnglishEventCode.ValueName)
	assertEqual(t, "Amber info english event code value", "CAE", infoEnglishEventCode.Value)

	// Info english area
	infoEnglishArea := infoEnglish.Area[0] // only one area
	assertEqual(t, "Amber info english area description", "Los Angeles County", infoEnglishArea.AreaDesc)
	assertEqual(t, "Amber info english area geocode value name", "SAME", infoEnglishArea.Geocode[0].ValueName)
	assertEqual(t, "Amber info english area geocode value", "006037", infoEnglishArea.Geocode[0].Value)

	infoSpanish := alert.Info[1] // spanish
	assertEqual(t, "Amber info spanish language", "es-US", infoSpanish.Language)
	assertEqual(t, "Amber info spanish category", "Rescue", infoSpanish.Category[0].String())
	assertEqual(t, "Amber info spanish event", "Abducción de Niño", infoSpanish.Event)
	assertEqual(t, "Amber info spanish urgency", "Immediate", infoSpanish.Urgency.String())
	assertEqual(t, "Amber info spanish severity", "Severe", infoSpanish.Severity.String())
	assertEqual(t, "Amber info spanish certainty", "Likely", infoSpanish.Certainty.String())
	assertEqual(t, "Amber info spanish sender name", "Departamento de Policía de Los Ángeles - LAPD", infoSpanish.SenderName)
	assertEqual(t, "Amber info spanish headline", "Alerta Amber en el condado de Los Ángeles", infoSpanish.Headline)
	assertEqual(t, "Amber info spanish description", `DATE/TIME: 06/11/03, 1915 HORAS. VÍCTIMAS: KHAYRI DOE JR. M/B BLK/BRO 3'0", 40 LIBRAS. TEZ LIGERA. DOB 06/24/01. CORTOCIRCUITOS ROJOS QUE USAN, CAMISETA BLANCA, COLLAR DE W/BLUE. LOCALIZACIÓN: 5721 DOE ST., LOS ÁNGELES. SOSPECHOSO: KHAYRI DOE ST. DOB 04/18/71 M/B, PELO DEL NEGRO, OJO DE BRO. VEHÍCULO: 81' BUICK 2-DR, AZUL (4XXX000)`, infoSpanish.Description)
	assertEqual(t, "Amber info spanish contact", "DET. SMITH, 77TH DIV, LOS ANGELES POLICE DEPT-LAPD AT 213 485-2389", infoSpanish.Contact)

	// Info spanish event codes
	infoSpanishEventCode := infoSpanish.EventCode[0] // only one event code
	assertEqual(t, "Amber info spanish event code value name", "SAME", infoSpanishEventCode.ValueName)
	assertEqual(t, "Amber info spanish event code value", "CAE", infoSpanishEventCode.Value)
}

// TestPelmorexNAADSWindWarning checks an Environment Canada NAADS message.
func TestPelmorexNAADSWindWarning(t *testing.T) {
	alert := parseFixture(t, "testing/PelmorexNAADS_WindWarning.xml")

	// Alert section
	assertEqual(t, "Wind identifier", "urn:oid:2.49.0.1.124.3936999913.2019", alert.Identifier)
	assertEqual(t, "Wind sender", "cap-pac@canada.ca", alert.Sender)
	assertEqual(t, "Wind sent", "2019-01-09T02:17:03-00:00", alert.Sent.String())
	assertEqual(t, "Wind status", "Actual", alert.Status.String())
	assertEqual(t, "Wind message type", "Update", alert.MsgType.String())
	assertEqual(t, "Wind source", "Env. Can. - Can. Met. Ctr. – Montréal", alert.Source)
	assertEqual(t, "Wind scope", "Public", alert.Scope.String())
	assertEqual(t, "Wind note", `Notification de service: Des changements au PAC d’ECCC, et qui sont d’importance aux utilisateurs, sont en développement pour un possible lancement au printemps 2019 (ou plus tard). Afin d’avoir accès aux notifications dès qu’elles sont disponibles, vous êtes invités à vous inscrire à la liste de diffusion suivante: http://lists.cmc.ec.gc.ca/mailman/listinfo/dd_info | Service Notice: Changes to ECCC CAP, of importance to users of ECCC CAP, are in development for a possible Spring 2019 release (or later). To have access to notices as they become available you are invited to subscribe to the following mailing list: http://lists.cmc.ec.gc.ca/mailman/listinfo/dd_info`, alert.Note)
	assertEqual(t, "Wind references", `cap-pac@canada.ca,urn:oid:2.49.0.1.124.0642871265.2019,2019-01-08T19:55:40-00:00 cap-pac@canada.ca,urn:oid:2.49.0.1.124.2407362607.2019,2019-01-08T19:56:40-00:00 cap-pac@canada.ca,urn:oid:2.49.0.1.124.2177735585.2019,2019-01-09T02:16:03-00:00`, alert.References.String())
	assertEqual(t, "Wind reference singleton", `cap-pac@canada.ca,urn:oid:2.49.0.1.124.0642871265.2019,2019-01-08T19:55:40-00:00`, alert.References.Values()[0])

	// Info sections
	infoFrench := alert.Info[0] // french
	assertEqual(t, "Wind info french language", "fr-CA", infoFrench.Language)
	assertEqual(t, "Wind info french category", "Met", infoFrench.Category[0].String())
	assertEqual(t, "Wind info french event", "vent", infoFrench.Event)
	assertEqual(t, "Wind info french response type", "Monitor", infoFrench.ResponseType[0].String())
	assertEqual(t, "Wind info french urgency", "Future", infoFrench.Urgency.String())
	assertEqual(t, "Wind info french severity", "Moderate", infoFrench.Severity.String())
	assertEqual(t, "Wind info french certainty", "Likely", infoFrench.Certainty.String())
	assertEqual(t, "Wind info french audience", "grand public", infoFrench.Audience)
	assertEqual(t, "Wind info french effective", "2019-01-09T02:16:03-00:00", infoFrench.Effective.String())
	assertEqual(t, "Wind info french expires", "2019-01-09T18:16:03-00:00", infoFrench.Expires.String())
	assertEqual(t, "Wind info french sender name", "Environnement Canada", infoFrench.SenderName)
	assertEqual(t, "Wind info french headline", "avertissement de vent en vigueur", infoFrench.Headline)
	assertEqual(t, "Wind info french description", `
Des vents forts pouvant causer des dommages soufflent ou souffleront.

Une dépression s'approchant depuis l'ouest gagnera la région mercredi. Elle se dirigera ensuite lentement vers le nord-est pour se trouver près des îles d'ici jeudi soir.

Les vents du sud-est devraient augmenter d'intensité mercredi et souffleront en rafales atteignant 100 km/h d'ici mercredi après-midi. Ces très fortes rafales devraient diminuer d'intensité tard mercredi soir ou vers minuit.

De plus, la neige à l'avant de ce système commencera à tomber mercredi matin avant de se changer en pluie d'ici mercredi soir. On prévoit actuellement de 10 à 15 centimètres de neige. Des vents du sud-est avec rafales jusqu'à 100 km/h réduiront la visibilité dans la poudrerie.

De plus, ces vents forts du sud-est produiront des niveaux d'eaux plus élevés que la normale, de hautes vagues et un ressac pilonnant, lors de la marée haute tard mercredi soir.

###

Les bâtiments pourraient être endommagés (bardeaux de toiture, fenêtres brisées).

Un avertissement de vent est émis lorsqu'il y a un risque important que des vents destructeurs soufflent.

Veuillez continuer à surveiller les alertes et les prévisions émises par Environnement Canada. Pour signaler du temps violent, envoyez un courriel à meteoNS@canada.ca ou publiez un gazouillis en utilisant le mot-clic #NSMeteo.
`, infoFrench.Description)
	assertEqual(t, "Wind info french web", "http://meteo.gc.ca/warnings/index_f.html?prov=sqc", infoFrench.Web)

	// Info french event codes
	infoFrenchEventCode := infoFrench.EventCode
	assertEqual(t, "Wind info french event code 0 value name", "profile:CAP-CP:Event:0.4", infoFrenchEventCode[0].ValueName)
	assertEqual(t, "Wind info french event code 0 value", "wind", infoFrenchEventCode[0].Value)
	assertEqual(t, "Wind info french event code 1 value name", "SAME", infoFrenchEventCode[1].ValueName)
	assertEqual(t, "Wind info french event code 1 value", "HWW", infoFrenchEventCode[1].Value)

	// Info french parameters Check the first and last parameters.
	infoFrenchParams := infoFrench.Parameter
	assertEqual(t, "Wind info french parameter 0 value name", "layer:EC-MSC-SMC:1.0:Alert_Type", infoFrenchParams[0].ValueName)
	assertEqual(t, "Wind info french parameter 0 value", "warning", infoFrenchParams[0].Value)
	assertEqual(t, "Wind info french parameter 10 value name", "layer:SOREM:2.0:WirelessImmediate", infoFrenchParams[10].ValueName)
	assertEqual(t, "Wind info french parameter 10 value", "No", infoFrenchParams[10].Value)

	// Info french area
	infoFrenchArea := infoFrench.Area[0] // only one area
	assertEqual(t, "Wind info french area description", "Îles-de-la-Madeleine", infoFrenchArea.AreaDesc)
	assertEqual(t, "Wind info french area polygon", "47.1947,-61.7255 47.1824,-62.1106 47.4783,-62.0336 47.8867,-61.5042 47.8207,-61.344 47.5211,-61.322 47.1947,-61.7255", infoFrenchArea.Polygon[0].String())
	assertEqual(t, "Wind info french area polygon singleton", "47.1947,-61.7255", infoFrenchArea.Polygon[0].Values()[0])
	assertEqual(t, "Wind info french area geocode 0 value name", "layer:EC-MSC-SMC:1.0:CLC", infoFrenchArea.Geocode[0].ValueName)
	assertEqual(t, "Wind info french area geocode 0 value", "036800", infoFrenchArea.Geocode[0].Value)
	assertEqual(t, "Wind info french area geocode 1 value name", "profile:CAP-CP:Location:0.3", infoFrenchArea.Geocode[1].ValueName)
	assertEqual(t, "Wind info french area geocode 1 value", "2401", infoFrenchArea.Geocode[1].Value)

	// Info sections
	infoEnglish := alert.Info[1] // english
	assertEqual(t, "Wind info english language", "en-CA", infoEnglish.Language)
	assertEqual(t, "Wind info english category", "Met", infoEnglish.Category[0].String())
	assertEqual(t, "Wind info english event", "wind", infoEnglish.Event)
	assertEqual(t, "Wind info english response type", "Monitor", infoEnglish.ResponseType[0].String())
	assertEqual(t, "Wind info english urgency", "Future", infoEnglish.Urgency.String())
	assertEqual(t, "Wind info english severity", "Moderate", infoEnglish.Severity.String())
	assertEqual(t, "Wind info english certainty", "Likely", infoEnglish.Certainty.String())
	assertEqual(t, "Wind info english audience", "general public", infoEnglish.Audience)
	assertEqual(t, "Wind info english effective", "2019-01-09T02:16:03-00:00", infoEnglish.Effective.String())
	assertEqual(t, "Wind info english expires", "2019-01-09T18:16:03-00:00", infoEnglish.Expires.String())
	assertEqual(t, "Wind info english sender name", "Environment Canada", infoEnglish.SenderName)
	assertEqual(t, "Wind info english headline", "wind warning in effect", infoEnglish.Headline)
	assertEqual(t, "Wind info english description", `
Strong winds that may cause damage are expected or occurring.

A low pressure system approaching from the west will move into the region on Wednesday. It will then slowly track northeastward to lie near the islands by Thursday evening.

Southeasterly winds are expected to strengthen during Wednesday and reach 100 km/h gusts by Wednesday afternoon. These very strong gusts are expected to diminish late Wednesday evening, or near midnight.

Additionally, snow ahead of this system will begin Wednesday morning before changing to rain by Wednesday evening. Snowfall amounts of 10 to 15 centimetres are currently forecast. Southeasterly winds gusting up to 100 km/h will reduce visibility in blowing snow.

Furthermore, these strong southeasterly winds will generate higher than normal water levels, high waves, and pounding surf, at high tide late Wednesday evening.

###

Damage to buildings, such as to roof shingles and windows, may occur.

Wind warnings are issued when there is a significant risk of damaging winds.

Please continue to monitor alerts and forecasts issued by Environment Canada. To report severe weather, send an email to NSstorm@canada.ca or tweet reports using #NSStorm.
`, infoEnglish.Description)
	assertEqual(t, "Wind info english web", "http://weather.gc.ca/warnings/index_e.html?prov=sqc", infoEnglish.Web)

	// Info english event codes
	infoEnglishEventCode := infoEnglish.EventCode
	assertEqual(t, "Wind info english event code 0 value name", "profile:CAP-CP:Event:0.4", infoEnglishEventCode[0].ValueName)
	assertEqual(t, "Wind info english event code 0 value", "wind", infoEnglishEventCode[0].Value)
	assertEqual(t, "Wind info english event code 1 value name", "SAME", infoEnglishEventCode[1].ValueName)
	assertEqual(t, "Wind info english event code 1 value", "HWW", infoEnglishEventCode[1].Value)

	// Info english parameters Check the first and last parameters.
	infoEnglishParams := infoEnglish.Parameter
	assertEqual(t, "Wind info english parameter 0 value name", "layer:EC-MSC-SMC:1.0:Alert_Type", infoEnglishParams[0].ValueName)
	assertEqual(t, "Wind info english parameter 0 value", "warning", infoEnglishParams[0].Value)
	assertEqual(t, "Wind info english parameter 10 value name", "layer:SOREM:2.0:WirelessImmediate", infoEnglishParams[10].ValueName)
	assertEqual(t, "Wind info english parameter 10 value", "No", infoEnglishParams[10].Value)

	// Info english area
	infoEnglishArea := infoEnglish.Area[0] // only one area
	assertEqual(t, "Wind info english area description", "Îles-de-la-Madeleine", infoEnglishArea.AreaDesc)
	assertEqual(t, "Wind info english area polygon", "47.1947,-61.7255 47.1824,-62.1106 47.4783,-62.0336 47.8867,-61.5042 47.8207,-61.344 47.5211,-61.322 47.1947,-61.7255", infoEnglishArea.Polygon[0].String())
	assertEqual(t, "Wind info english area polygon singleton", "47.1947,-61.7255", infoEnglishArea.Polygon[0].Values()[0])
	assertEqual(t, "Wind info english area geocode 0 value name", "layer:EC-MSC-SMC:1.0:CLC", infoEnglishArea.Geocode[0].ValueName)
	assertEqual(t, "Wind info english area geocode 0 value", "036800", infoEnglishArea.Geocode[0].Value)
	assertEqual(t, "Wind info english area geocode 1 value name", "profile:CAP-CP:Location:0.3", infoEnglishArea.Geocode[1].ValueName)
	assertEqual(t, "Wind info english area geocode 1 value", "2401", infoEnglishArea.Geocode[1].Value)
}

// TestParseMultiplePolygons checks repeated polygon elements.
func TestParseMultiplePolygons(t *testing.T) {
	data := []byte(`<alert xmlns="urn:oasis:names:tc:emergency:cap:1.2">
	<identifier>multiple-polygons</identifier>
	<sender>example.com</sender>
	<sent>2020-01-01T00:00:00-00:00</sent>
	<status>Test</status>
	<msgType>Alert</msgType>
	<scope>Public</scope>
	<info>
		<category>Geo</category>
		<event>Test</event>
		<urgency>Unknown</urgency>
		<severity>Unknown</severity>
		<certainty>Unknown</certainty>
		<area>
			<areaDesc>Two regions</areaDesc>
			<polygon>45,-75  46,-75
				46,-74 45,-75</polygon>
			<polygon>47,-73 48,-73 48,-72 47,-73</polygon>
		</area>
	</info>
</alert>`)

	alert, err := cap.ParseCAP(data)
	if err != nil {
		t.Fatal(err)
	}

	polygons := alert.Info[0].Area[0].Polygon
	if len(polygons) != 2 {
		t.Fatalf("expected 2 polygons, got %d", len(polygons))
	}
	assertEqual(t, "first polygon", "45,-75 46,-75 46,-74 45,-75", polygons[0].String())
	assertEqual(t, "second polygon", "47,-73 48,-73 48,-72 47,-73", polygons[1].String())
}

// TestParseRejectsForeignCAPElement checks namespace enforcement.
func TestParseRejectsForeignCAPElement(t *testing.T) {
	data, err := cap.MarshalCAP(validAlert(t))
	if err != nil {
		t.Fatal(err)
	}
	data = []byte(strings.Replace(string(data), "<identifier>", `<identifier xmlns="urn:example">`, 1))
	if _, err := cap.ParseCAP(data); err == nil {
		t.Fatal("expected foreign namespace error")
	}
}

// TestParseRejectsMultipleRoots checks XML document structure.
func TestParseRejectsMultipleRoots(t *testing.T) {
	data := []byte(`<alert xmlns="urn:oasis:names:tc:emergency:cap:1.2"></alert><alert xmlns="urn:oasis:names:tc:emergency:cap:1.2"></alert>`)
	if _, err := cap.ParseCAP(data); err == nil {
		t.Fatal("expected multiple root error")
	}
}
