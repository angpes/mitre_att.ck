import requests as req
from requests.sessions import Session

from bs4 import BeautifulSoup as BS
import xlsxwriter

session = Session()


with open("tactics.csv", encoding="utf-8") as file:
    lines = file.readlines()

tactics = [
           # 'reconnaissance',
           # 'resource-development',
           # 'initial-access',
           # 'execution',
           # 'persistence',
           # 'privilege-escalation',
           # 'defense-evasion',
           # 'credential-access',
           # 'discovery',
           'lateral-movement',
           'collection',
           # 'command-and-control',
           # 'exfiltration',
           # 'impact'
]

data = []
keys = ["tactic", "technique", "technique_id", "technique_name"]
for line in lines[1:]:
    data.append({keys[i]: line.split(",")[i] for i in range(4)})

techniques = [d for d in data if "." not  in d["technique_id"]]
subtechniques = [d for d in data if "." in d["technique_id"]]

data_dicts = dict()
for tactic in tactics:
    data_dicts[tactic] = [d for d in subtechniques if d["tactic"] == tactic]


def write_technique_url(worksheet, tid, idx):
    worksheet.write_url(idx + 2, 0,
                        url=f'https://attack.mitre.org/techniques/{tid.replace(")", "").split(" (")[1].strip()}',
                        string=t_and_id)

def write_subtechnique_url(worksheet, stid, stname, idx):
    worksheet.write_url(idx + 2, 1,
                        url=f'https://attack.mitre.org/techniques/{stid.replace(".", "/")}',
                        string=stname.split("(")[0].strip())
    worksheet.write_url(idx + 2, 2,
                        url=f'https://attack.mitre.org/techniques/{stid.replace(".", "/")}',
                        string=stid)
    mitigations = get_mitigations(stid)
    worksheet.write(idx + 2, 4, mitigations)


def get_mitigations(stid, only_id=True):
    url = f'https://attack.mitre.org/techniques/{stid.replace(".", "/")}'
    soup = BS(session.get(url).content, features="lxml")
    hrefs = [a.get("href") for a in soup.findAll("a")]
    mitigations = set([f"https://attack.mitre.org{h}" for h in hrefs if "mitigations/M" in h])
    if only_id:
        return ", ".join([m.split("/")[-1] for m in mitigations])
    else:
        return ", ".join(mitigations)




workbook = xlsxwriter.Workbook('mitre_attck2.xlsx')

headers = ["Technique and ID", "Sub-techniques", "Sub-technique ID", "Tools", "Mitigation ID"]

for tactic in tactics:
    worksheet = workbook.add_worksheet(tactic.replace("-", " ").capitalize())
    worksheet.write(0, 0, tactic.replace("-", " ").capitalize())
    for i in range(len(headers)):
        worksheet.write(1, i, headers[i])
    for i, technique in enumerate(data_dicts[tactic]):
        t_and_id = [t for t in techniques if t["technique"] == technique["technique"]][0]["technique_name"].strip()
        write_technique_url(worksheet, t_and_id, i)
        write_subtechnique_url(worksheet, technique["technique_id"], technique["technique_name"], i)






workbook.close()