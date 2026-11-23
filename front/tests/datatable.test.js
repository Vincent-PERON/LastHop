import { describe, it, expect } from 'vitest'
import { mount } from '@vue/test-utils'
import DataTable from '../src/components/DataTable.vue'

const columns = [
  { accessorKey: 'mac', header: 'MAC' },
  { accessorKey: 'alias', header: 'Alias' },
]

describe('DataTable (TanStack Table v9)', () => {
  it('rend les en-têtes et les lignes', () => {
    const w = mount(DataTable, { props: { columns, data: [{ id: 1, mac: 'aa:bb', alias: 'x' }, { id: 2, mac: 'cc:dd', alias: null }] } })
    expect(w.findAll('th').map((t) => t.text())).toEqual(['MAC', 'Alias'])
    expect(w.findAll('tbody tr')).toHaveLength(2)
    expect(w.text()).toContain('cc:dd')
  })

  it('échappe le contenu hostile (aucun élément injecté)', () => {
    const evil = '<script>alert(1)</script><img src=x onerror=alert(2)>'
    const w = mount(DataTable, { props: { columns, data: [{ id: 1, mac: 'aa', alias: evil }] } })
    expect(w.find('td[data-col="alias"]').text()).toBe(evil)
    expect(w.find('script').exists()).toBe(false)
    expect(w.find('img').exists()).toBe(false)
  })

  it('affiche un message vide et réagit aux changements de données', async () => {
    const w = mount(DataTable, { props: { columns, data: [], empty: 'Rien' } })
    expect(w.text()).toContain('Rien')
    await w.setProps({ data: [{ id: 9, mac: 'zz', alias: 'a' }] })
    expect(w.text()).toContain('zz')
    expect(w.text()).not.toContain('Rien')
  })

  it('émet row-click au clic et au clavier quand clickable', async () => {
    const w = mount(DataTable, { props: { columns, clickable: true, data: [{ id: 1, mac: 'aa', alias: 'x' }] } })
    await w.find('tbody tr').trigger('click')
    await w.find('tbody tr').trigger('keydown.enter')
    expect(w.emitted('row-click')).toHaveLength(2)
  })
})
