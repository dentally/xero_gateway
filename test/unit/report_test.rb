require File.join(File.dirname(__FILE__), '../test_helper.rb')

class ReportTest < Test::Unit::TestCase
  include TestHelper
  include REXML

  context "creating report object" do
    should "create bank statement" do
      report = create_test_report_bank_statement
      assert_equal 'BankStatement', report.report_id
      assert_equal 'BankStatement', report.report_name
      assert_equal 'BankStatement', report.report_type
      assert report.report_titles.is_a? Array
      assert report.report_date.is_a? Date
      assert report.updated_at.is_a? Time
      assert report.column_names.is_a? Array
      assert report.body.is_a? Array
    end
  end

  context :from_xml do
    context "with a bank statement report" do
      setup do
        @report = make_report_from_xml("bank_statement")
      end

      should "create a bank statement report" do
        assert @report.is_a?(XeroGateway::Report)
        assert_equal [], @report.errors
        assert_equal Date.parse("27 May 2014"), @report.report_date
        assert_equal "BankStatement", @report.report_id
        assert_equal "Bank Statement", @report.report_name
        expected_titles = ["Bank Statement", "Business Bank Account", "Demo Company (NZ)", "From 1 May 2014 to 27 May 2014"]
        assert_equal expected_titles, @report.report_titles
        assert_equal "BankStatement", @report.report_type
        assert_equal Time.parse("2014-05-26 22:36:07 +0000").to_i, @report.updated_at.to_i
        expected_names = { :column_1=>"Date", :column_2=>"Description", :column_3=>"Reference", :column_4=>"Reconciled", :column_5=>"Source", :column_6=>"Amount", :column_7=>"Balance" }
        assert_equal expected_names, @report.column_names

        ###
        # REPORT BODY
        assert @report.body.is_a?(Array)

        # First = Opening Balance
        first_statement = @report.body.first
        assert_equal "2014-05-01T00:00:00", first_statement.date
        assert_equal "Opening Balance", first_statement.description
        assert_equal nil, first_statement.reference
        assert_equal nil, first_statement.reconciled
        assert_equal nil, first_statement.source
        assert_equal nil, first_statement.amount
        assert_equal "15461.97", first_statement.balance

        # Second = Bank Transaction/Statement
        second_statement = @report.body.second
        assert_equal "2014-05-01T00:00:00", second_statement.date
        assert_equal "Ridgeway Banking Corporation", second_statement.description
        assert_equal "Fee", second_statement.reference
        assert_equal "No", second_statement.reconciled
        assert_equal "Import", second_statement.source
        assert_equal "-15.00", second_statement.amount
        assert_equal "15446.97", second_statement.balance

        # Third
        third_statement = @report.body.third
        assert_equal nil, third_statement.description.value # no description, but other attributes
        assert_equal "Eft", third_statement.reference
        assert_equal "No", third_statement.reconciled
        assert_equal "Import", third_statement.source
        assert_equal "-15.75", third_statement.amount
        assert_equal "15431.22", third_statement.balance
      end
    end

    context "with a trial balance report" do
      setup do
        @report = make_report_from_xml("trial_balance")
      end

      should "set attributes on individual cells" do
        first_statement = @report.body.first
        assert_equal "Sales (200)", first_statement.account.value
        assert_equal({ account: "7d05a53d-613d-4eb2-a2fc-dcb6adb80b80" }, first_statement.account.attributes)
      end

      should "have all rows and section titles" do
        assert_equal 15, @report.rows.length
        assert_equal %w(Revenue Expenses Assets Liabilities Equity), @report.rows.map(&:section_name).uniq.compact
      end
    end

  end

  private

  def make_report_from_xml(report_name = "bank_statement")
    xml_response = get_file("reports/#{report_name}.xml")
    xml_response.gsub!(/\n +/,'')
    xml_doc = REXML::Document.new(xml_response)
    xpath_report = XPath.first(xml_doc, "//Report")
    XeroGateway::Report.from_xml(xpath_report)
  end

end
