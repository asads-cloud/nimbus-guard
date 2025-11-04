variable "account_id" { 
    description = "AWS Account ID" 
    type = string 
}

variable "region"     { 
    description = "AWS Region"      
    type = string 
    default = "eu-west-1"
}

variable "github_org" { 
    description = "GitHub org/user" 
    type = string
}

variable "repo_name"  { 
    description = "Repo name"       
    type = string 
    default = "nimbus-guard"
}
