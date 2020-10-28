const metaData = `
lastModifiedDate:2020-10-27T18:01:52-04:00\r\n
size:7680682\r\n
zipSize:527727\r\n
gzSize:527583\r\n
sha256:3B7EBF83BAF9435BCACE6B2C36BC20EAC62800F09EB8323BDCC62BC66DCC7D40
`;

const nvd = {
    "CVE_data_type" : "CVE",
    "CVE_data_format" : "MITRE",
    "CVE_data_version" : "4.0",
    "CVE_data_numberOfCVEs" : "293",
    "CVE_data_timestamp" : "2020-07-10T22:00Z",
    "CVE_Items" : [ 
    {
      "cve" : {
        "data_type" : "CVE",
        "data_format" : "MITRE",
        "data_version" : "4.0",
        "CVE_data_meta" : {
          "ID" : "CVE-2019-19417",
          "ASSIGNER" : "cve@mitre.org"
        },
        "problemtype" : {
          "problemtype_data" : [ {
            "description" : [ ]
          } ]
        },
        "references" : {
          "reference_data" : [ {
            "url" : "https://www.huawei.com/en/psirt/security-advisories/huawei-sa-20200115-01-sip-en",
            "name" : "https://www.huawei.com/en/psirt/security-advisories/huawei-sa-20200115-01-sip-en",
            "refsource" : "CONFIRM",
            "tags" : [ ]
          } ]
        },
        "description" : {
          "description_data" : [ {
            "lang" : "en",
            "value" : "The SIP module of some Huawei products have a denial of service (DoS) vulnerability. A remote attacker could exploit these three vulnerabilities by sending the specially crafted messages to the affected device. Due to the insufficient verification of the packets, successful exploit could allow the attacker to cause buffer overflow and dead loop, leading to DoS condition. Affected products can be found in https://www.huawei.com/en/psirt/security-advisories/huawei-sa-20200115-01-sip-en."
          } ]
        }
      },
      "configurations" : {
        "CVE_data_version" : "4.0",
        "nodes" : [ ]
      },
      "impact" : { },
      "publishedDate" : "2020-07-08T17:15Z",
      "lastModifiedDate" : "2020-07-08T17:29Z"
    }, {
      "cve" : {
        "data_type" : "CVE",
        "data_format" : "MITRE",
        "data_version" : "4.0",
        "CVE_data_meta" : {
          "ID" : "CVE-2019-19935",
          "ASSIGNER" : "cve@mitre.org"
        },
        "problemtype" : {
          "problemtype_data" : [ {
            "description" : [ ]
          } ]
        },
        "references" : {
          "reference_data" : [ {
            "url" : "http://packetstormsecurity.com/files/158300/Froala-WYSIWYG-HTML-Editor-3.1.1-Cross-Site-Scripting.html",
            "name" : "http://packetstormsecurity.com/files/158300/Froala-WYSIWYG-HTML-Editor-3.1.1-Cross-Site-Scripting.html",
            "refsource" : "MISC",
            "tags" : [ ]
          }, {
            "url" : "https://github.com/froala/wysiwyg-editor/compare/v3.0.5...v3.0.6",
            "name" : "https://github.com/froala/wysiwyg-editor/compare/v3.0.5...v3.0.6",
            "refsource" : "MISC",
            "tags" : [ ]
          } ]
        },
        "description" : {
          "description_data" : [ {
            "lang" : "en",
            "value" : "Froala Editor before 3.0.6 allows XSS."
          } ]
        }
      },
      "configurations" : {
        "CVE_data_version" : "4.0",
        "nodes" : [ ]
      },
      "impact" : { },
      "publishedDate" : "2020-07-07T16:15Z",
      "lastModifiedDate" : "2020-07-07T16:57Z"
    }, {
      "cve" : {
        "data_type" : "CVE",
        "data_format" : "MITRE",
        "data_version" : "4.0",
        "CVE_data_meta" : {
          "ID" : "CVE-2019-20418",
          "ASSIGNER" : "cve@mitre.org"
        },
        "problemtype" : {
          "problemtype_data" : [ {
            "description" : [ {
              "lang" : "en",
              "value" : "NVD-CWE-noinfo"
            } ]
          } ]
        },
        "references" : {
          "reference_data" : [ {
            "url" : "https://jira.atlassian.com/browse/JRASERVER-70943",
            "name" : "N/A",
            "refsource" : "N/A",
            "tags" : [ "Issue Tracking", "Vendor Advisory" ]
          } ]
        },
        "description" : {
          "description_data" : [ {
            "lang" : "en",
            "value" : "Affected versions of Atlassian Jira Server and Data Center allow remote attackers to prevent users from accessing the instance via an Application Denial of Service vulnerability in the /rendering/wiki endpoint. The affected versions are before version 8.8.0."
          } ]
        }
      },
      "configurations" : {
        "CVE_data_version" : "4.0",
        "nodes" : [ {
          "operator" : "OR",
          "cpe_match" : [ {
            "vulnerable" : true,
            "cpe23Uri" : "cpe:2.3:a:atlassian:jira:*:*:*:*:*:*:*:*",
            "versionEndExcluding" : "8.8.0"
          }, {
            "vulnerable" : true,
            "cpe23Uri" : "cpe:2.3:a:atlassian:jira_software_data_center:*:*:*:*:*:*:*:*",
            "versionEndExcluding" : "8.8.0"
          } ]
        } ]
      },
      "impact" : {
        "baseMetricV3" : {
          "cvssV3" : {
            "version" : "3.1",
            "vectorString" : "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H",
            "attackVector" : "NETWORK",
            "attackComplexity" : "LOW",
            "privilegesRequired" : "LOW",
            "userInteraction" : "NONE",
            "scope" : "UNCHANGED",
            "confidentialityImpact" : "NONE",
            "integrityImpact" : "NONE",
            "availabilityImpact" : "HIGH",
            "baseScore" : 6.5,
            "baseSeverity" : "MEDIUM"
          },
          "exploitabilityScore" : 2.8,
          "impactScore" : 3.6
        },
        "baseMetricV2" : {
          "cvssV2" : {
            "version" : "2.0",
            "vectorString" : "AV:N/AC:L/Au:S/C:N/I:N/A:P",
            "accessVector" : "NETWORK",
            "accessComplexity" : "LOW",
            "authentication" : "SINGLE",
            "confidentialityImpact" : "NONE",
            "integrityImpact" : "NONE",
            "availabilityImpact" : "PARTIAL",
            "baseScore" : 4.0
          },
          "severity" : "MEDIUM",
          "exploitabilityScore" : 8.0,
          "impactScore" : 2.9,
          "acInsufInfo" : false,
          "obtainAllPrivilege" : false,
          "obtainUserPrivilege" : false,
          "obtainOtherPrivilege" : false,
          "userInteractionRequired" : false
        }
      },
      "publishedDate" : "2020-07-03T01:15Z",
      "lastModifiedDate" : "2020-07-09T18:05Z"
    }, {
      "cve" : {
        "data_type" : "CVE",
        "data_format" : "MITRE",
        "data_version" : "4.0",
        "CVE_data_meta" : {
          "ID" : "CVE-2019-20419",
          "ASSIGNER" : "cve@mitre.org"
        },
        "problemtype" : {
          "problemtype_data" : [ {
            "description" : [ {
              "lang" : "en",
              "value" : "CWE-426"
            } ]
          } ]
        },
        "references" : {
          "reference_data" : [ {
            "url" : "https://jira.atlassian.com/browse/JRASERVER-70945",
            "name" : "https://jira.atlassian.com/browse/JRASERVER-70945",
            "refsource" : "MISC",
            "tags" : [ "Issue Tracking", "Vendor Advisory" ]
          } ]
        },
        "description" : {
          "description_data" : [ {
            "lang" : "en",
            "value" : "Affected versions of Atlassian Jira Server and Data Center allow remote attackers to execute arbitrary code via a DLL hijacking vulnerability in Tomcat. The affected versions are before version 8.5.5, and from version 8.6.0 before 8.7.2."
          } ]
        }
      },
      "configurations" : {
        "CVE_data_version" : "4.0",
        "nodes" : [ {
          "operator" : "OR",
          "cpe_match" : [ {
            "vulnerable" : true,
            "cpe23Uri" : "cpe:2.3:a:atlassian:jira:*:*:*:*:*:*:*:*",
            "versionEndExcluding" : "8.5.5"
          }, {
            "vulnerable" : true,
            "cpe23Uri" : "cpe:2.3:a:atlassian:jira:*:*:*:*:*:*:*:*",
            "versionStartIncluding" : "8.6.0",
            "versionEndExcluding" : "8.7.2"
          }, {
            "vulnerable" : true,
            "cpe23Uri" : "cpe:2.3:a:atlassian:jira_software_data_center:*:*:*:*:*:*:*:*",
            "versionEndExcluding" : "8.5.5"
          }, {
            "vulnerable" : true,
            "cpe23Uri" : "cpe:2.3:a:atlassian:jira_software_data_center:*:*:*:*:*:*:*:*",
            "versionStartIncluding" : "8.6.0",
            "versionEndExcluding" : "8.7.2"
          } ]
        } ]
      },
      "impact" : {
        "baseMetricV3" : {
          "cvssV3" : {
            "version" : "3.1",
            "vectorString" : "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
            "attackVector" : "LOCAL",
            "attackComplexity" : "LOW",
            "privilegesRequired" : "NONE",
            "userInteraction" : "REQUIRED",
            "scope" : "UNCHANGED",
            "confidentialityImpact" : "HIGH",
            "integrityImpact" : "HIGH",
            "availabilityImpact" : "HIGH",
            "baseScore" : 7.8,
            "baseSeverity" : "HIGH"
          },
          "exploitabilityScore" : 1.8,
          "impactScore" : 5.9
        },
        "baseMetricV2" : {
          "cvssV2" : {
            "version" : "2.0",
            "vectorString" : "AV:L/AC:M/Au:N/C:P/I:P/A:P",
            "accessVector" : "LOCAL",
            "accessComplexity" : "MEDIUM",
            "authentication" : "NONE",
            "confidentialityImpact" : "PARTIAL",
            "integrityImpact" : "PARTIAL",
            "availabilityImpact" : "PARTIAL",
            "baseScore" : 4.4
          },
          "severity" : "MEDIUM",
          "exploitabilityScore" : 3.4,
          "impactScore" : 6.4,
          "acInsufInfo" : false,
          "obtainAllPrivilege" : false,
          "obtainUserPrivilege" : false,
          "obtainOtherPrivilege" : false,
          "userInteractionRequired" : true
        }
      },
      "publishedDate" : "2020-07-03T02:15Z",
      "lastModifiedDate" : "2020-07-09T18:15Z"
    }, {
      "cve" : {
        "data_type" : "CVE",
        "data_format" : "MITRE",
        "data_version" : "4.0",
        "CVE_data_meta" : {
          "ID" : "CVE-2019-20894",
          "ASSIGNER" : "cve@mitre.org"
        },
        "problemtype" : {
          "problemtype_data" : [ {
            "description" : [ {
              "lang" : "en",
              "value" : "CWE-295"
            } ]
          } ]
        },
        "references" : {
          "reference_data" : [ {
            "url" : "https://github.com/containous/traefik/issues/5312",
            "name" : "https://github.com/containous/traefik/issues/5312",
            "refsource" : "MISC",
            "tags" : [ "Exploit", "Issue Tracking", "Third Party Advisory" ]
          } ]
        },
        "description" : {
          "description_data" : [ {
            "lang" : "en",
            "value" : "Traefik 2.x, in certain configurations, allows HTTPS sessions to proceed without mutual TLS verification in a situation where ERR_BAD_SSL_CLIENT_AUTH_CERT should have occurred."
          } ]
        }
      },
      "configurations" : {
        "CVE_data_version" : "4.0",
        "nodes" : [ {
          "operator" : "OR",
          "cpe_match" : [ {
            "vulnerable" : true,
            "cpe23Uri" : "cpe:2.3:a:containous:traefik:*:*:*:*:*:*:*:*",
            "versionStartIncluding" : "2.0.0",
            "versionEndExcluding" : "2.0.1"
          } ]
        } ]
      },
      "impact" : {
        "baseMetricV3" : {
          "cvssV3" : {
            "version" : "3.1",
            "vectorString" : "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            "attackVector" : "NETWORK",
            "attackComplexity" : "LOW",
            "privilegesRequired" : "NONE",
            "userInteraction" : "NONE",
            "scope" : "UNCHANGED",
            "confidentialityImpact" : "HIGH",
            "integrityImpact" : "NONE",
            "availabilityImpact" : "NONE",
            "baseScore" : 7.5,
            "baseSeverity" : "HIGH"
          },
          "exploitabilityScore" : 3.9,
          "impactScore" : 3.6
        },
        "baseMetricV2" : {
          "cvssV2" : {
            "version" : "2.0",
            "vectorString" : "AV:N/AC:M/Au:N/C:P/I:N/A:N",
            "accessVector" : "NETWORK",
            "accessComplexity" : "MEDIUM",
            "authentication" : "NONE",
            "confidentialityImpact" : "PARTIAL",
            "integrityImpact" : "NONE",
            "availabilityImpact" : "NONE",
            "baseScore" : 4.3
          },
          "severity" : "MEDIUM",
          "exploitabilityScore" : 8.6,
          "impactScore" : 2.9,
          "acInsufInfo" : false,
          "obtainAllPrivilege" : false,
          "obtainUserPrivilege" : false,
          "obtainOtherPrivilege" : false,
          "userInteractionRequired" : false
        }
      },
      "publishedDate" : "2020-07-02T16:15Z",
      "lastModifiedDate" : "2020-07-08T16:55Z"
    }, {
      "cve" : {
        "data_type" : "CVE",
        "data_format" : "MITRE",
        "data_version" : "4.0",
        "CVE_data_meta" : {
          "ID" : "CVE-2019-20896",
          "ASSIGNER" : "cve@mitre.org"
        },
        "problemtype" : {
          "problemtype_data" : [ {
            "description" : [ {
              "lang" : "en",
              "value" : "CWE-89"
            } ]
          } ]
        },
        "references" : {
          "reference_data" : [ {
            "url" : "https://sourceforge.net/p/webchess/bugs/81/",
            "name" : "https://sourceforge.net/p/webchess/bugs/81/",
            "refsource" : "CONFIRM",
            "tags" : [ "Issue Tracking", "Third Party Advisory" ]
          } ]
        },
        "description" : {
          "description_data" : [ {
            "lang" : "en",
            "value" : "WebChess 1.0 allows SQL injection via the messageFrom, gameID, opponent, messageID, or to parameter."
          } ]
        }
      },
      "configurations" : {
        "CVE_data_version" : "4.0",
        "nodes" : [ {
          "operator" : "OR",
          "cpe_match" : [ {
            "vulnerable" : true,
            "cpe23Uri" : "cpe:2.3:a:webchess_project:webchess:1.0:*:*:*:*:*:*:*"
          } ]
        } ]
      },
      "impact" : {
        "baseMetricV3" : {
          "cvssV3" : {
            "version" : "3.1",
            "vectorString" : "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "attackVector" : "NETWORK",
            "attackComplexity" : "LOW",
            "privilegesRequired" : "NONE",
            "userInteraction" : "NONE",
            "scope" : "UNCHANGED",
            "confidentialityImpact" : "HIGH",
            "integrityImpact" : "HIGH",
            "availabilityImpact" : "HIGH",
            "baseScore" : 9.8,
            "baseSeverity" : "CRITICAL"
          },
          "exploitabilityScore" : 3.9,
          "impactScore" : 5.9
        },
        "baseMetricV2" : {
          "cvssV2" : {
            "version" : "2.0",
            "vectorString" : "AV:N/AC:L/Au:N/C:P/I:P/A:P",
            "accessVector" : "NETWORK",
            "accessComplexity" : "LOW",
            "authentication" : "NONE",
            "confidentialityImpact" : "PARTIAL",
            "integrityImpact" : "PARTIAL",
            "availabilityImpact" : "PARTIAL",
            "baseScore" : 7.5
          },
          "severity" : "HIGH",
          "exploitabilityScore" : 10.0,
          "impactScore" : 6.4,
          "acInsufInfo" : false,
          "obtainAllPrivilege" : false,
          "obtainUserPrivilege" : false,
          "obtainOtherPrivilege" : false,
          "userInteractionRequired" : false
        }
      },
      "publishedDate" : "2020-07-07T19:15Z",
      "lastModifiedDate" : "2020-07-09T16:24Z"
    }, {
      "cve" : {
        "data_type" : "CVE",
        "data_format" : "MITRE",
        "data_version" : "4.0",
        "CVE_data_meta" : {
          "ID" : "CVE-2019-4323",
          "ASSIGNER" : "cve@mitre.org"
        },
        "problemtype" : {
          "problemtype_data" : [ {
            "description" : [ ]
          } ]
        },
        "references" : {
          "reference_data" : [ {
            "url" : "https://support.hcltechsw.com/csm?id=kb_article&sysparm_article=KB0080572",
            "name" : "https://support.hcltechsw.com/csm?id=kb_article&sysparm_article=KB0080572",
            "refsource" : "MISC",
            "tags" : [ ]
          }, {
            "url" : "https://support.hcltechsw.com/csm?id=kb_article&sysparm_article=KB0080572&sys_kb_id=3668a078dbb9101855f38d6d13961955",
            "name" : "https://support.hcltechsw.com/csm?id=kb_article&sysparm_article=KB0080572&sys_kb_id=3668a078dbb9101855f38d6d13961955",
            "refsource" : "CONFIRM",
            "tags" : [ ]
          } ]
        },
        "description" : {
          "description_data" : [ {
            "lang" : "en",
            "value" : "\"HCL AppScan Enterprise advisory API documentation is susceptible to clickjacking, which could allow an attacker to embed the contents of untrusted web pages in a frame.\""
          } ]
        }
      },
      "configurations" : {
        "CVE_data_version" : "4.0",
        "nodes" : [ ]
      },
      "impact" : { },
      "publishedDate" : "2020-07-07T15:15Z",
      "lastModifiedDate" : "2020-07-07T16:57Z"
    }, {
      "cve" : {
        "data_type" : "CVE",
        "data_format" : "MITRE",
        "data_version" : "4.0",
        "CVE_data_meta" : {
          "ID" : "CVE-2019-4324",
          "ASSIGNER" : "cve@mitre.org"
        },
        "problemtype" : {
          "problemtype_data" : [ {
            "description" : [ ]
          } ]
        },
        "references" : {
          "reference_data" : [ {
            "url" : "https://support.hcltechsw.com/csm?id=kb_article&sys_id=cd5030b4dbbd101855f38d6d13961958",
            "name" : "https://support.hcltechsw.com/csm?id=kb_article&sys_id=cd5030b4dbbd101855f38d6d13961958",
            "refsource" : "CONFIRM",
            "tags" : [ ]
          }, {
            "url" : "https://support.hcltechsw.com/csm?id=kb_article&sysparm_article=KB0080574",
            "name" : "https://support.hcltechsw.com/csm?id=kb_article&sysparm_article=KB0080574",
            "refsource" : "MISC",
            "tags" : [ ]
          } ]
        },
        "description" : {
          "description_data" : [ {
            "lang" : "en",
            "value" : "\"HCL AppScan Enterprise is susceptible to Cross-Site Scripting while importing a specially crafted test policy.\""
          } ]
        }
      },
      "configurations" : {
        "CVE_data_version" : "4.0",
        "nodes" : [ ]
      },
      "impact" : { },
      "publishedDate" : "2020-07-07T15:15Z",
      "lastModifiedDate" : "2020-07-07T16:57Z"
    }, {
      "cve" : {
        "data_type" : "CVE",
        "data_format" : "MITRE",
        "data_version" : "4.0",
        "CVE_data_meta" : {
          "ID" : "CVE-2019-8066",
          "ASSIGNER" : "cve@mitre.org"
        },
        "problemtype" : {
          "problemtype_data" : [ {
            "description" : [ ]
          } ]
        },
        "references" : {
          "reference_data" : [ {
            "url" : "https://helpx.adobe.com/security/products/acrobat/apsb19-41.html",
            "name" : "https://helpx.adobe.com/security/products/acrobat/apsb19-41.html",
            "refsource" : "CONFIRM",
            "tags" : [ ]
          } ]
        },
        "description" : {
          "description_data" : [ {
            "lang" : "en",
            "value" : "Adobe Acrobat and Reader versions 2019.012.20035 and earlier, 2019.012.20035 and earlier, 2017.011.30142 and earlier, 2017.011.30143 and earlier, 2015.006.30497 and earlier, and 2015.006.30498 and earlier have a heap overflow vulnerability. Successful exploitation could lead to arbitrary code execution ."
          } ]
        }
      },
      "configurations" : {
        "CVE_data_version" : "4.0",
        "nodes" : [ ]
      },
      "impact" : { },
      "publishedDate" : "2020-07-06T18:15Z",
      "lastModifiedDate" : "2020-07-06T18:17Z"
    }, {
      "cve" : {
        "data_type" : "CVE",
        "data_format" : "MITRE",
        "data_version" : "4.0",
        "CVE_data_meta" : {
          "ID" : "CVE-2020-9498",
          "ASSIGNER" : "cve@mitre.org"
        },
        "problemtype" : {
          "problemtype_data" : [ {
            "description" : [ {
              "lang" : "en",
              "value" : "CWE-119"
            } ]
          } ]
        },
        "references" : {
          "reference_data" : [ {
            "url" : "https://kb.pulsesecure.net/articles/Pulse_Security_Advisories/SA44525",
            "name" : "https://kb.pulsesecure.net/articles/Pulse_Security_Advisories/SA44525",
            "refsource" : "CONFIRM",
            "tags" : [ "Third Party Advisory" ]
          }, {
            "url" : "https://lists.apache.org/thread.html/r26fb170edebff842c74aacdb1333c1338f0e19e5ec7854d72e4680fc@%3Cannounce.apache.org%3E",
            "name" : "[announce] 20200701 [SECURITY] CVE-2020-9498: Apache Guacamole: Dangling pointer in RDP static virtual channel handling",
            "refsource" : "MLIST",
            "tags" : [ "Mailing List", "Third Party Advisory" ]
          }, {
            "url" : "https://lists.apache.org/thread.html/rff824b38ebd2fddc726b816f0e509696b83b9f78979d0cd021ca623b%40%3Cannounce.guacamole.apache.org%3E",
            "name" : "https://lists.apache.org/thread.html/rff824b38ebd2fddc726b816f0e509696b83b9f78979d0cd021ca623b%40%3Cannounce.guacamole.apache.org%3E",
            "refsource" : "MISC",
            "tags" : [ "Mailing List", "Third Party Advisory" ]
          }, {
            "url" : "https://research.checkpoint.com/2020/apache-guacamole-rce/",
            "name" : "https://research.checkpoint.com/2020/apache-guacamole-rce/",
            "refsource" : "MISC",
            "tags" : [ "Third Party Advisory" ]
          } ]
        },
        "description" : {
          "description_data" : [ {
            "lang" : "en",
            "value" : "Apache Guacamole 1.1.0 and older may mishandle pointers involved inprocessing data received via RDP static virtual channels. If a userconnects to a malicious or compromised RDP server, a series ofspecially-crafted PDUs could result in memory corruption, possiblyallowing arbitrary code to be executed with the privileges of therunning guacd process."
          } ]
        }
      },
      "configurations" : {
        "CVE_data_version" : "4.0",
        "nodes" : [ {
          "operator" : "OR",
          "cpe_match" : [ {
            "vulnerable" : true,
            "cpe23Uri" : "cpe:2.3:a:apache:guacamole:*:*:*:*:*:*:*:*",
            "versionEndIncluding" : "1.1.0"
          } ]
        } ]
      },
      "impact" : {
        "baseMetricV3" : {
          "cvssV3" : {
            "version" : "3.1",
            "vectorString" : "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
            "attackVector" : "NETWORK",
            "attackComplexity" : "LOW",
            "privilegesRequired" : "NONE",
            "userInteraction" : "REQUIRED",
            "scope" : "UNCHANGED",
            "confidentialityImpact" : "HIGH",
            "integrityImpact" : "HIGH",
            "availabilityImpact" : "HIGH",
            "baseScore" : 8.8,
            "baseSeverity" : "HIGH"
          },
          "exploitabilityScore" : 2.8,
          "impactScore" : 5.9
        },
        "baseMetricV2" : {
          "cvssV2" : {
            "version" : "2.0",
            "vectorString" : "AV:N/AC:M/Au:N/C:C/I:C/A:C",
            "accessVector" : "NETWORK",
            "accessComplexity" : "MEDIUM",
            "authentication" : "NONE",
            "confidentialityImpact" : "COMPLETE",
            "integrityImpact" : "COMPLETE",
            "availabilityImpact" : "COMPLETE",
            "baseScore" : 9.3
          },
          "severity" : "HIGH",
          "exploitabilityScore" : 8.6,
          "impactScore" : 10.0,
          "acInsufInfo" : false,
          "obtainAllPrivilege" : false,
          "obtainUserPrivilege" : false,
          "obtainOtherPrivilege" : false,
          "userInteractionRequired" : true
        }
      },
      "publishedDate" : "2020-07-02T13:15Z",
      "lastModifiedDate" : "2020-07-08T17:06Z"
    } ]
  }
  
  module.exports = {
    metaData,
    nvd,
  };