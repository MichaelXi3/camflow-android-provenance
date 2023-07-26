#ifndef PROVENANCE_PROVENANCEW3CJSON_H
#define PROVENANCE_PROVENANCEW3CJSON_H

void set_W3CJSON_callback( void (*fcn)(char* json) );
void flush_json( void );
void append_activity(char* json_element);
void append_agent(char* json_element);
void append_entity(char* json_element);
void append_message(char* json_element);
void append_relation(char* json_element);
void append_used(char* json_element);
void append_generated(char* json_element);
void append_informed(char* json_element);
void append_influenced(char* json_element);
void append_associated(char* json_element);
void append_derived(char* json_element);

/* struct to json functions */
/* TODO provide clean implementation? right now probably highly inneficient */
char* used_to_json(struct relation_struct* e);
char* generated_to_json(struct relation_struct* e);
char* informed_to_json(struct relation_struct* e);
char* influenced_to_json(struct relation_struct* e);
char* associated_to_json(struct relation_struct* e);
char* derived_to_json(struct relation_struct* e);
char* disc_to_json(struct disc_node_struct* n);
char* proc_to_json(struct proc_prov_struct* n);
char* task_to_json(struct task_prov_struct* n);
char* inode_to_json(struct inode_prov_struct* n);
char* sb_to_json(struct sb_struct* n);
char* msg_to_json(struct msg_msg_struct* n);
char* shm_to_json(struct shm_struct* n);
char* packet_to_json(struct pck_struct* n);
char* str_msg_to_json(struct str_struct* n);
char* addr_to_json(struct address_struct* n);
char* pathname_to_json(struct file_name_struct* n);
const char* prefix_json();
char* machine_to_json(struct machine_struct *m);
char* iattr_to_json(struct iattr_prov_struct* n);
char* xattr_to_json(struct xattr_prov_struct* n);
char* pckcnt_to_json(struct pckcnt_struct* n);
char* arg_to_json(struct arg_struct* n);

#endif //PROVENANCE_PROVENANCEW3CJSON_H
