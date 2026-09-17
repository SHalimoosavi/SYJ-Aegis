from dataclasses import dataclass,asdict
@dataclass(frozen=True)
class Evidence:
    file:str; line:int; detection:str
@dataclass(frozen=True)
class Finding:
    rule_id:str; name:str; category:str; severity:str; confidence:str; description:str; evidence:Evidence; remediation:str; source:str="LOCAL STATIC FINDING"
    def to_dict(self):
        return {"rule_id":self.rule_id,"name":self.name,"category":self.category,"severity":self.severity,"confidence":self.confidence,"description":self.description,"evidence":asdict(self.evidence),"remediation":self.remediation,"source":self.source,"status":"OPEN"}
