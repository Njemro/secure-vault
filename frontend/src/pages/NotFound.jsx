import PageHeader from '../components/PageHeader.jsx'

export default function NotFound() {
  return (
    <section>
      <PageHeader title="Page not found" subtitle="That page does not exist." />
      <p className="page__body">
        Use the navigation above to get back to a known page.
      </p>
    </section>
  )
}
