from lxml import etree

namespaces = {
    'oval': 'http://oval.mitre.org/XMLSchema/oval-definitions-5',
    'xsi': 'http://www.w3.org/2001/XMLSchema-instance',
    'unix-def': 'http://oval.mitre.org/XMLSchema/oval-definitions-5#unix',
    'red-def': 'http://oval.mitre.org/XMLSchema/oval-definitions-5#linux',
    'ind-def': 'http://oval.mitre.org/XMLSchema/oval-definitions-5#independent',
}

class Definition:
    def __init__(self, def_id, def_class, title, description, severity, references, affected_cpes, criterias, cvss):
        self.id = def_id
        self.def_class = def_class
        self.title = title
        self.description = description
        self.severity = severity
        self.references = references
        self.affected_cpes = affected_cpes
        self.criterias = criterias
        self.cvss = cvss

class Test:
    def __init__(self, t_id, check, comment, object_ref, state_ref):
        self.id = t_id
        self.check = check
        self.comment = comment
        self.object_ref = object_ref
        self.state_ref = state_ref

class Object:
    def __init__(self, id, name, epoch, arch, version, release, behaviors):
        self.id = id
        self.name = name
        self.epoch = epoch
        self.arch = arch
        self.version = version
        self.release = release
        self.behaviors = behaviors

class State:
    def __init__(self, id, arch, evr):
        self.id = id
        self.arch = arch
        self.evr = evr

def parse_tests(root):
    final_test = {}
    tests = root.find('oval:tests', namespaces=namespaces)
    test_list = tests.findall('red-def:rpminfo_test', namespaces=namespaces)
    test_verify_list  = tests.findall('red-def:rpmverifyfile_test', namespaces=namespaces)
    #print(test_list)
    try:
        for t in test_list:
            if 'signed with Red Hat redhatrelease2 key' not in t.attrib.get('comment'):
                t_id = t.attrib.get('id')
                check = t.attrib.get('check')
                comment = t.attrib.get('comment')
                object_ref = t.find('.//red-def:object', namespaces=namespaces).attrib.get('object_ref')
                state_ref = t.find('.//red-def:state', namespaces=namespaces).attrib.get('state_ref')
                test = Test(
                    t_id, check, comment, object_ref, state_ref
                )

            final_test[t_id] = test

        for t in test_verify_list:
            if 'signed with Red Hat redhatrelease2 key' not in t.attrib.get('comment'):
                t_id = t.attrib.get('id')
                check = t.attrib.get('check')
                comment = t.attrib.get('comment')
                object_ref = t.find('.//red-def:object', namespaces=namespaces).attrib.get('object_ref')
                state_ref = t.find('.//red-def:state', namespaces=namespaces).attrib.get('state_ref')
                test = Test(
                    t_id, check, comment, object_ref, state_ref
                )

            final_test[t_id] = test
    except:
        pass
#    print(final_test['oval:com.redhat.rhba:tst:20192715001'].comment)
 #   print(final_test['oval:com.redhat.rhba:tst:20192715002'].object_ref)
 #   print(final_test['oval:com.redhat.rhba:tst:20192715002'].state_ref)
    return final_test

def parse_objects(root):
    final_object = {}
    objects = root.find('oval:objects', namespaces=namespaces)
    object_list = objects.findall('red-def:rpminfo_object', namespaces=namespaces)
    object_file_verify_list = objects.findall('red-def:rpmverifyfile_object', namespaces=namespaces)
    try:
        for o in object_list:
            o_id = o.attrib.get('id')
            name = o.findtext('.//red-def:name', namespaces=namespaces)
            epoch = 0
            arch = 0
            version = 0
            release = 0
            behaviors = 0
            object_ = Object(
                o_id, name, epoch, arch, version, release, behaviors
            )

            final_object[o_id] = object_

        for o in object_file_verify_list:
            o_id = o.attrib.get('id')
            name = o.find('.//red-def:name', namespaces=namespaces).attrib.get('operation')
            epoch = o.find('.//red-def:epoch', namespaces=namespaces).attrib.get('operation')
            arch = o.find('.//red-def:arch', namespaces=namespaces).attrib.get('operation')
            version = o.find('.//red-def:version', namespaces=namespaces).attrib.get('operation')
            release = o.find('.//red-def:release', namespaces=namespaces).attrib.get('operation')
            behaviors = o.find('.//red-def:behaviors', namespaces=namespaces).attrib.get('noconfigfiles')
            object_ = Object(
                o_id, name, epoch, arch, version, release, behaviors
            )

            final_object[o_id] = object_
    except:
        pass
#    print(final_object['oval:com.redhat.rhba:obj:20192715010'].name)
    #print(final_test['oval:com.redhat.rhba:tst:20192715002'].state_ref)

    return final_object

def parse_states(root):
    final_state = {}
    states = root.find('oval:states', namespaces)
    state_list = states.findall('red-def:rpminfo_state', namespaces=namespaces)
    evr = 0
    arch = 0
    oper_evr = 0
    oper_arch = 0
 #   try:
    for s in state_list:
        s_id = s.attrib.get('id')
        evr_obj = s.find('.//red-def:evr', namespaces=namespaces)
        evr = s.findtext('.//red-def:evr', namespaces=namespaces)
        arch_obj = s.find('.//red-def:arch', namespaces=namespaces)
        arch = s.findtext('.//red-def:arch', namespaces=namespaces)
        try:
            oper_evr = evr_obj.attrib.get('operation')
            oper_arch = arch_obj.attrib.get('operation')
        except:
            pass
        state = State(
            s_id, str(oper_arch)+' '+str(arch), str(oper_evr)+' '+str(evr)
        )

        final_state[s_id] = state
#    except:
#        pass
#    print(final_state['oval:com.redhat.rhba:ste:20192715017'].evr)
#    print(final_state['oval:com.redhat.rhba:ste:20192715017'].arch)
#    print(final_state['oval:com.redhat.rhba:ste:20191992001'].evr)
#    print(final_state['oval:com.redhat.rhba:ste:20191992001'].arch)

    return final_state

def parse_oval_file(file_path):
    tree = etree.parse(file_path)
    root = tree.getroot()
    definitions = root.find('oval:definitions', namespaces=namespaces)
    definition_list = definitions.findall('oval:definition', namespaces=namespaces)

    tests = parse_tests(root)
    objects = parse_objects(root)
    states = parse_states(root)
    full_defs = {}

    for d in definition_list:
        def_id = d.attrib.get('id')
        def_class = d.attrib.get('class')
        title = d.findtext('oval:metadata/oval:title', namespaces=namespaces).split('(')[0]
        description = d.findtext('oval:metadata/oval:description', namespaces=namespaces)
        severity = d.findtext('oval:metadata/oval:advisory/oval:severity', namespaces=namespaces)
        refs = [ref.attrib.get('ref_id') for ref in d.findall('oval:metadata/oval:reference', namespaces=namespaces)]
        cpes = [c.text for c in d.findall('oval:metadata/oval:advisory/oval:affected_cpe_list/oval:cpe', namespaces=namespaces)]
        cvss = [(str(cve.text)+' '+str(cve.attrib.get('cvss3'))) for cve in d.findall('oval:metadata/oval:advisory/oval:cve', namespaces=namespaces)]
        criteria = d.findall('.//oval:criteria', namespaces=namespaces)
        criterias = []
        for i in criteria:
            criteria_text = ''
            operator = str(i.attrib.get('operator'))
            for c in i.findall('.//oval:criterion', namespaces=namespaces):
                if 'signed with Red Hat redhatrelease2 key' not in c.attrib.get('comment'):
                    if criteria_text=='':
                        criteria_text += c.attrib.get('comment') + ' (test: '+c.attrib.get('test_ref')+')'
                    else:
                        criteria_text += ' '+operator+' '+c.attrib.get('comment') + ' (test: '+c.attrib.get('test_ref')+')'
            criterias.append(criteria_text)

        definition = Definition(
            def_id, def_class, title, description, severity,
            refs, cpes, criterias, cvss
        )

        full_defs[def_id] = definition

    return full_defs, tests, objects, states

def definitions_to_xml(definitions):
    defs_el = etree.Element("definitions")
    for definition in definitions.keys():
        def_el = etree.SubElement(defs_el, "definition", id=definitions[definition].id, **{"class": definitions[definition].def_class})
        etree.SubElement(def_el, "title").text = definitions[definition].title
        etree.SubElement(def_el, "description").text = definitions[definition].description
        etree.SubElement(def_el, "severity").text = definitions[definition].severity

        refs_el = etree.SubElement(def_el, "references")
        for ref in definitions[definition].references:
            etree.SubElement(refs_el, "reference").text = ref

        cpes_el = etree.SubElement(def_el, "affected_cpes")
        for cpe in definitions[definition].affected_cpes:
            etree.SubElement(cpes_el, "cpe").text = cpe

        criterias_el = etree.SubElement(def_el, "criterias")
        for crit in definitions[definition].criterias:
            etree.SubElement(criterias_el, "criteria").text = crit
        
        cvss_el = etree.SubElement(def_el, "cvss")
        for cvss_info in definitions[definition].cvss:
            etree.SubElement(cvss_el, "cvss_info").text = cvss_info

    return defs_el

def tests_to_xml(tests):
    tests_el = etree.Element("tests")
    for test in tests.keys():
        test_el = etree.SubElement(tests_el, "test", id=tests[test].id, check=tests[test].check)
        etree.SubElement(test_el, "comment").text = tests[test].comment
        etree.SubElement(test_el, "object_ref").text = tests[test].object_ref
        etree.SubElement(test_el, "state_ref").text = tests[test].state_ref
    return tests_el

def objects_to_xml(objects):
    objs_el = etree.Element("objects")
    for obj in objects.keys():
        obj_el = etree.SubElement(objs_el, "object", id=objects[obj].id)
        etree.SubElement(obj_el, "name").text = objects[obj].name
        if objects[obj].epoch!=0:
            etree.SubElement(obj_el, "epoch").text = objects[obj].epoch
        if objects[obj].version!=0:
            etree.SubElement(obj_el, "version").text = objects[obj].version
        if objects[obj].arch!=0:
            etree.SubElement(obj_el, "arch").text = objects[obj].arch
        if objects[obj].release!=0:
            etree.SubElement(obj_el, "release").text = objects[obj].release
        if objects[obj].behaviors!=0:
            etree.SubElement(obj_el, "behaviors").text = objects[obj].behaviors
    return objs_el

def states_to_xml(states):
    states_el = etree.Element("states")
    for state in states.keys():
        state_el = etree.SubElement(states_el, "state", id=states[state].id)
        etree.SubElement(state_el, "arch").text = states[state].arch
        etree.SubElement(state_el, "evr").text = states[state].evr
    return states_el

def save_to_xml(filename, definitions, tests, objects, states):
    root = etree.Element("oval_data")

    root.append(definitions_to_xml(definitions))
    root.append(tests_to_xml(tests))
    root.append(objects_to_xml(objects))
    root.append(states_to_xml(states))

    tree = etree.ElementTree(root)
    tree.write(filename, encoding="utf-8", pretty_print=True, xml_declaration=True)

if __name__ == "__main__":
    oval_file = "rhel-8.oval.xml"
    definitions, tests, objects, states = parse_oval_file(oval_file)

    try:
        request = str(input())
        if request=='save':
            save_to_xml("result.xml", definitions, tests, objects, states)
        else:
            print('Title: '+str(definitions[request].title)+'\n'+'Definition class: '+str(definitions[request].def_class)+'\n'+'Description: '+str(definitions[request].description)+'\n'+'Severity: '+str(definitions[request].severity)+'\n'+'CVSS 3.0: '+str(definitions[request].cvss)+'\n'+'References: '+str(definitions[request].references)+'\n'+'Affected CPEs: '+str(definitions[request].affected_cpes)+'\n'+'Criterias: '+str(definitions[request].criterias)+'\n')
    except:
        pass