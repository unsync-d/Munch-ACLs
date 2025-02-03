# Munch-ACLs: Active Directory ACL Enumeration Tool
This cmdlet was created while studying for the Altered Security's CRTE exam. It provides a method to easily list the most relevant ACLs that allow compromised users to interact with other AD objects. Besides BloodHound and Find-InterestingDomainAcl from PowerView with filters applied, I don't know of any tools that do this in a concise way. Hence, I used this opportunit to better understand how ACLs work. The things that I tried to prioritize while writing this cmdlet were readability and ease of use.

![PowerShell Version](https://img.shields.io/badge/PowerShell-5.1+-blue.svg)
[![AD Module Required](https://img.shields.io/badge/Requires-AD--Module-green.svg)]()

## Features

- **Operation Modes**: 
  - `-OUT`: Check privileges subjects have over other AD objects
  - `-IN`: Check privileges others have over specified subjects
- **Risk-Prioritized Output**: Color-coded high-risk permissions
- **Stealth Features**: Jitter delays and batch processing
- **Customizable Checks**: Define specific privileges to investigate
- **Cross-Domain Support**: Analyze different domains

>[!WARNING]  
>Although *-Jitter* and *-BatchSize* options try to make this cmdlet stealthier, the truth is that it is performing a noticeable enumeration in a relatively short amount of time. The effectiveness of these parameters hasn't been tested against MDI yet.

> [!TIP]
> *-IN* mode is available because it made sense to add it. However, the default mode is -OUT because it is the one that really does a good job in summarizing the exploitable ACLs in the direction **COMPROMISED USERS/GROUPS -> OBJECTS**, which is the functionality that I was looking for when I first starting developing Munch-ACLs.

## Usage
### Basic Commands
**Check privileges for specific users/groups:**
```powershell
Munch-ACLs -Users "admin1","admin2" -Groups "Admins" -OUT
```
**Check who has privileges over specified subjects:**
```powershell
Munch-ACLs -Users "CEO_User" -IN
```
**Custom privilege check with stealth options**
```powershell
Munch-ACLs -Privs "WriteDacl,ForceChangePassword" -Jitter 500 -BatchSize 15
```
# Munch-ACLs: Parameters Reference

## Parameters Reference

| Parameter   | Description                           | Default |
|------------|-----------------------------------|---------|
| `-Users`   | Target user accounts (comma-separated) | None    |
| `-Groups`  | Target security groups            | None    |
| `-Domain`  | Specify target domain             | Current |
| `-Privs`   | Custom privilege list             | [See below] |
| `-IN`      | Check privileges over subjects    | `$false` |
| `-OUT`     | Check privileges subjects have    | `$false` |
| `-Jitter`  | Random delay between operations (ms) | `0` |
| `-BatchSize` | Objects per processing batch    | `10` |

### Default Privileges Checked:
```text
GenericAll, WriteDacl, WriteOwner, AllExtendedRights, ForceChangePassword,
GenericWrite, WriteProperty, CreateChild, FullControl
```

---

## Output Interpretation

### Color-Coded Results
- 🔴 **Red**: Critical permissions (`GenericAll`, `WriteDacl`, `WriteOwner`)
- 🔵 **Cyan**: Standard permissions
- 🟢 **Green**: Summary table with key relationships

### Sample Output:
```text
=== HIGH RISK PERMISSIONS ===
[Group] Authenticated Users -> [OU] Finance : GenericAll 

=== OTHER PERMISSIONS ===
[User] BackupSvc -> [Computer] DC01 : WriteProperty

=== SUMMARY TABLE ===
Subject          SubjectType  Target        TargetType  Permission
-------          -----------  ------        ----------  ----------
Authenticated... Security...  Finance OU    OU          GenericAll!!
BackupSvc        User         DC01          Computer    WriteProperty
```

---

## Advanced Usage

### Cross-Domain Analysis
```powershell
Munch-ACLs -Domain "child.domain.com" -Groups "CrossDomainAdmins" -OUT
```

### Full Stealth Mode
```powershell
Munch-ACLs -Users "RedTeam" -Jitter 1000 -BatchSize 5
```

### Export Results
```powershell
Munch-ACLs -Groups "HelpDesk" -OUT | Export-Csv -Path .\results.csv
```


